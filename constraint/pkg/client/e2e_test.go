package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/instrumentation"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/topdown/print"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

func TestClient_Review(t *testing.T) {
	tests := []struct {
		name                              string
		namespaces                        []string
		targets                           []handler.TargetHandler
		templates                         []*templates.ConstraintTemplate
		constraints                       []*unstructured.Unstructured
		inventory                         []*handlertest.Object
		toReview                          interface{}
		enforcementPointFromReview        string
		enforcementPointSupportedByClient []string
		wantResults                       []*types.Result
		wantErr                           error
	}{
		{
			name:        "empty client",
			namespaces:  nil,
			targets:     []handler.TargetHandler{&handlertest.Handler{}},
			toReview:    handlertest.NewReview("", "foo", "bar"),
			wantResults: nil,
		},
		{
			name:       "deny missing Constraint",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			toReview:    handlertest.NewReview("", "foo", "bar"),
			wantResults: nil,
		},
		{
			name:    "deny all",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			}},
		},
		{
			name:    "deny all wihtout enforcementAction",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraintWithoutActions(t, clienttest.KindDeny, "constraint"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			}},
		},
		{
			name:    "wrong review type",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview:    handlertest.Object{Name: "foo"},
			wantErr:     &clienterrors.ErrorMap{handlertest.TargetName: client.ErrReview},
			wantResults: nil,
		},
		{
			name:    "ignored review",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview:    handlertest.Review{Ignored: true, Object: handlertest.Object{Name: "foo"}},
			wantErr:     nil,
			wantResults: nil,
		},
		{
			name:    "deny all duplicate Constraint",
			targets: []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			}},
		},
		{
			name:       "deny all dryrun",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDeny, "constraint", cts.EnforcementAction("dryrun")),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				EnforcementAction: "dryrun",
				Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "constraint", cts.EnforcementAction("dryrun")),
			}},
		},
		{
			name:       "deny all library",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDenyImport(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindDenyImport, "constraint"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied with library",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindDenyImport, "constraint"),
			}},
		},
		{
			name:       "allow all",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateAllow(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindAllow, "constraint"),
			},
			toReview:    handlertest.NewReview("", "foo", "bar"),
			wantResults: nil,
		},
		{
			name:       "check data allow",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint", cts.WantData("bar")),
			},
			toReview:    handlertest.NewReview("", "foo", "bar"),
			wantResults: nil,
		},
		{
			name:       "check data deny",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint", cts.WantData("bar")),
			},
			toReview: handlertest.NewReview("", "foo", "qux"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "got qux but want bar for data",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindCheckData, "constraint", cts.WantData("bar")),
			}},
		},
		{
			name:       "rego runtime error",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateRuntimeError(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindRuntimeError, "constraint"),
			},
			toReview: handlertest.NewReview("", "foo", "qux"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               `template:8: eval_conflict_error: functions must not produce multiple outputs for same inputs`,
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeConstraint(t, clienttest.KindRuntimeError, "constraint"),
			}},
		},
		{
			name:       "autoreject",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{Cache: &handlertest.Cache{}}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("aaa")),
			},
			toReview: handlertest.NewReview("aaa", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               `unable to match constraints: not found: namespace "aaa" not in cache`,
				EnforcementAction: string(constraints.Deny),
				Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("aaa")),
			}},
		},
		{
			name:       "autoreject and fail",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{Cache: &handlertest.Cache{}}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("aaa")),
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint2",
					cts.WantData("qux"), cts.EnforcementAction("warn")),
			},
			toReview: handlertest.NewReview("aaa", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               `unable to match constraints: not found: namespace "aaa" not in cache`,
				EnforcementAction: string(constraints.Deny),
				Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("aaa")),
			}, {
				Target:            handlertest.TargetName,
				Msg:               "got bar but want qux for data",
				EnforcementAction: "warn",
				Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint2",
					cts.WantData("qux"), cts.EnforcementAction("warn")),
			}},
		},
		{
			name:       "namespace matches",
			namespaces: []string{"billing"},
			targets: []handler.TargetHandler{&handlertest.Handler{
				Cache: &handlertest.Cache{},
			}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("billing")),
			},
			toReview: handlertest.NewReview("billing", "foo", "qux"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "got qux but want bar for data",
				EnforcementAction: string(constraints.Deny),
				Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("billing")),
			}},
		},
		{
			name:       "namespace does not match",
			namespaces: []string{"shipping"},
			targets: []handler.TargetHandler{&handlertest.Handler{
				Cache: &handlertest.Cache{},
			}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					cts.WantData("bar"), cts.MatchNamespace("billing")),
			},
			toReview:    handlertest.NewReview("shipping", "foo", "qux"),
			wantResults: nil,
		},
		{
			name:       "update Template target",
			namespaces: nil,
			targets: []handler.TargetHandler{
				&handlertest.Handler{
					Name: ptr.To[string]("foo1"),
				},
				&handlertest.Handler{
					Name: ptr.To[string]("foo2"),
				},
			},
			templates: []*templates.ConstraintTemplate{
				cts.New(cts.OptTargets(cts.Target("foo1", clienttest.ModuleAllow))),
				cts.New(cts.OptTargets(cts.Target("foo2", clienttest.ModuleDeny))),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, cts.MockTemplate, "bar"),
			},
			toReview: handlertest.NewReview("shipping", "foo", "qux"),
			wantResults: []*types.Result{{
				Target:            "foo2",
				Msg:               "denied",
				Constraint:        cts.MakeConstraint(t, cts.MockTemplate, "bar"),
				EnforcementAction: string(constraints.Deny),
			}},
		},
		{
			name:       "referential constraint allow",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateForbidDuplicates(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindForbidDuplicates, "constraint"),
			},
			inventory: []*handlertest.Object{{
				Name: "foo-1",
				Data: "bar",
			}},
			toReview:    handlertest.NewReview("", "foo-2", "qux"),
			wantResults: nil,
		},
		{
			name:       "referential constraint deny",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateForbidDuplicates(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindForbidDuplicates, "constraint"),
			},
			inventory: []*handlertest.Object{{
				Name: "foo-1",
				Data: "bar",
			}},
			toReview: handlertest.NewReview("", "foo-2", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "duplicate data bar",
				Constraint:        cts.MakeConstraint(t, clienttest.KindForbidDuplicates, "constraint"),
				EnforcementAction: string(constraints.Deny),
			}},
		},
		{
			name:       "deny future",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateFuture(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindFuture, "constraint"),
			},
			inventory: nil,
			toReview:  handlertest.NewReview("", "foo", "1"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "bad data",
				Constraint:        cts.MakeConstraint(t, clienttest.KindFuture, "constraint"),
				EnforcementAction: string(constraints.Deny),
			}},
		},
		{
			name:       "allow future",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateFuture(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeConstraint(t, clienttest.KindFuture, "constraint"),
			},
			inventory:   nil,
			toReview:    handlertest.NewReview("", "foo", "3"),
			wantResults: nil,
		},
		{
			name:       "deny with scoped audit EP",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "audit", "webhook"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:                   handlertest.TargetName,
				Msg:                      "denied",
				ScopedEnforcementActions: []string{string(constraints.Deny)},
				EnforcementAction:        string(constraints.Scoped),
				Constraint:               cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "audit", "webhook"),
			}},
			enforcementPointFromReview:        "audit",
			enforcementPointSupportedByClient: []string{"audit"},
		},
		{
			name:       "deny with scoped audit EP and webhook caller",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "audit"),
			},
			toReview:                          handlertest.NewReview("", "foo", "bar"),
			wantResults:                       nil,
			enforcementPointFromReview:        "webhook",
			enforcementPointSupportedByClient: []string{"audit"},
			wantErr:                           client.ErrUnsupportedEnforcementPoints,
		},
		{
			name:       "deny with scoped test EP and test caller",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:                   handlertest.TargetName,
				Msg:                      "denied",
				ScopedEnforcementActions: []string{string(constraints.Deny)},
				EnforcementAction:        string(constraints.Scoped),
				Constraint:               cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test"),
			}},
			enforcementPointFromReview:        "test",
			enforcementPointSupportedByClient: []string{"test"},
		},
		{
			name:       "scoped enforcement action without caller source EP in review",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:                   handlertest.TargetName,
				Msg:                      "denied",
				ScopedEnforcementActions: []string{string(constraints.Deny)},
				EnforcementAction:        string(constraints.Scoped),
				Constraint:               cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test"),
			}},
			enforcementPointFromReview:        "",
			enforcementPointSupportedByClient: []string{"test"},
		},
		{
			name:       "client initialized for all EP, specific scopedEnforcementActions in constraints, without sourceEP",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test", "audit"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:                   handlertest.TargetName,
				Msg:                      "denied",
				ScopedEnforcementActions: []string{string(constraints.Deny)},
				EnforcementAction:        string(constraints.Scoped),
				Constraint:               cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test", "audit"),
			}},
			enforcementPointFromReview:        "",
			enforcementPointSupportedByClient: []string{"test", "audit"},
		},
		{
			name:       "client initialized for all EP, specific scopedEnforcementActions in constraints, with sourceEP",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test", "audit"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:                   handlertest.TargetName,
				Msg:                      "denied",
				ScopedEnforcementActions: []string{string(constraints.Deny)},
				EnforcementAction:        string(constraints.Scoped),
				Constraint:               cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test", "audit"),
			}},
			enforcementPointFromReview:        "audit",
			enforcementPointSupportedByClient: []string{"test", "audit"},
		},
		{
			name:       "enforcementAction and scopedEnforcementAction provided. enforcementAction: deny with scoped enforcement action",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Deny), []string{string(constraints.Deny)}, "test"),
			},
			toReview: handlertest.NewReview("", "foo", "bar"),
			wantResults: []*types.Result{{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				EnforcementAction: string(constraints.Deny),
				Constraint:        cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Deny), []string{string(constraints.Deny)}, "test"),
			}},
			enforcementPointFromReview:        "",
			enforcementPointSupportedByClient: []string{"test"},
		},
		{
			name:       "case sensitive enforcement points",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "Test.gateKeeper.sh"),
			},
			toReview:                          handlertest.NewReview("", "foo", "bar"),
			wantResults:                       nil,
			wantErr:                           client.ErrUnsupportedEnforcementPoints,
			enforcementPointFromReview:        "teSt.gAtekeeper.sh",
			enforcementPointSupportedByClient: []string{"tEst.Gatekeeper.sh"},
		},
		{
			name:       "review caller is webhook and constraint is for audit",
			namespaces: nil,
			targets:    []handler.TargetHandler{&handlertest.Handler{}},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				cts.MakeScopedEnforcementConstraint(t, clienttest.KindDeny, "constraint", string(constraints.Scoped), []string{string(constraints.Deny)}, "test", "audit"),
			},
			toReview:                          handlertest.NewReview("", "foo", "bar"),
			wantResults:                       nil,
			enforcementPointFromReview:        "webhook",
			enforcementPointSupportedByClient: []string{"webhook"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			opts := []client.Opt{client.Targets(tt.targets...)}
			if tt.enforcementPointSupportedByClient != nil {
				opts = append(opts, client.EnforcementPoints(tt.enforcementPointSupportedByClient...))
			}

			c := clienttest.New(t, opts...)

			for _, ns := range tt.namespaces {
				_, err := c.AddData(ctx, &handlertest.Object{Namespace: ns})
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, ct := range tt.templates {
				_, err := c.AddTemplate(ctx, ct)
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, constraint := range tt.constraints {
				_, err := c.AddConstraint(ctx, constraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, obj := range tt.inventory {
				_, err := c.AddData(ctx, obj)
				if err != nil {
					t.Fatal(err)
				}
			}

			responses, err := c.Review(ctx, tt.toReview, reviews.EnforcementPoint(tt.enforcementPointFromReview))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			results := responses.Results()

			diffOpt := cmpopts.IgnoreFields(types.Result{}, "Metadata")
			if diff := cmp.Diff(tt.wantResults, results, diffOpt); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestClient_Review_Details(t *testing.T) {
	ctx := context.Background()

	c := clienttest.New(t)

	ct := clienttest.TemplateCheckData()
	_, err := c.AddTemplate(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}

	constraint := cts.MakeConstraint(t, clienttest.KindCheckData, "constraint", cts.WantData("bar"))
	_, err = c.AddConstraint(ctx, constraint)
	if err != nil {
		t.Fatal(err)
	}

	review := handlertest.Review{
		Object: handlertest.Object{
			Name: "foo",
			Data: "qux",
		},
	}

	responses, err := c.Review(ctx, review)
	if err != nil {
		t.Fatal(err)
	}

	want := []*types.Result{{
		Target:            handlertest.TargetName,
		Msg:               "got qux but want bar for data",
		EnforcementAction: string(constraints.Deny),
		Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
			cts.WantData("bar")),
		Metadata: map[string]interface{}{"details": map[string]interface{}{"got": "qux"}},
	}}

	results := responses.Results()

	if diff := cmp.Diff(want, results); diff != "" {
		t.Error(diff)
	}
}

type appendingPrintHook struct {
	printed *[]string
}

func (a appendingPrintHook) Print(_ print.Context, s string) error {
	*a.printed = append(*a.printed, s)
	return nil
}

func TestClient_Review_Print(t *testing.T) {
	testCases := []struct {
		name         string
		printEnabled bool
		wantResults  []*types.Result
		wantPrint    []string
	}{{
		name:         "Print enabled",
		printEnabled: true,
		wantResults: []*types.Result{
			{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				Constraint:        cts.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint"),
				EnforcementAction: string(constraints.Deny),
			},
		},
		wantPrint: []string{"denied!"},
	}, {
		name:         "Print disabled",
		printEnabled: false,
		wantResults: []*types.Result{
			{
				Target:            handlertest.TargetName,
				Msg:               "denied",
				Constraint:        cts.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint"),
				EnforcementAction: string(constraints.Deny),
			},
		},
		wantPrint: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			var printed []string
			printHook := appendingPrintHook{printed: &printed}

			d, err := rego.New(rego.PrintEnabled(tc.printEnabled), rego.PrintHook(printHook))
			if err != nil {
				t.Fatal(err)
			}

			c, err := client.NewClient(client.Targets(&handlertest.Handler{}), client.Driver(d), client.EnforcementPoints("audit"))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(ctx, clienttest.TemplateDenyPrint())
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}

			cstr := cts.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint")
			if _, err = c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}

			rsps, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "hanna"}})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			results := rsps.Results()
			if diff := cmp.Diff(tc.wantResults, results,
				cmpopts.IgnoreFields(types.Result{}, "Metadata")); diff != "" {
				t.Error(diff)
			}

			if diff := cmp.Diff(tc.wantPrint, printed); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2E_RemoveConstraint(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)

	_, err := c.AddTemplate(ctx, clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Target:            handlertest.TargetName,
		Msg:               "denied",
		Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: string(constraints.Deny),
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Metadata")); diff != "" {
		t.Fatal(diff)
	}

	_, err = c.RemoveConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses2, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got2 := responses2.Results()
	var want2 []*types.Result

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Metadata")); diff != "" {
		t.Fatal(diff)
	}
}

func TestE2E_RemoveTemplate(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)

	_, err := c.AddTemplate(ctx, clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Target:            handlertest.TargetName,
		Msg:               "denied",
		Constraint:        cts.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: string(constraints.Deny),
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Metadata")); diff != "" {
		t.Fatal(diff)
	}

	_, err = c.RemoveTemplate(ctx, clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	responses2, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got2 := responses2.Results()
	var want2 []*types.Result

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Metadata")); diff != "" {
		t.Fatal(diff)
	}
}

// TestE2E_Tracing checks that a Tracing(enabled/disabled) works as expected
// and that TraceDump reflects API consumer expectations.
func TestE2E_Tracing(t *testing.T) {
	tests := []struct {
		name           string
		tracingEnabled bool
		deny           bool
	}{
		{
			name:           "tracing disabled without violations",
			tracingEnabled: false,
			deny:           false,
		},
		{
			name:           "tracing enabled with violations",
			tracingEnabled: true,
			deny:           true,
		},
		{
			name:           "tracing disabled with violations",
			tracingEnabled: false,
			deny:           true,
		},
		{
			name:           "tracing enabled without violations",
			tracingEnabled: true,
			deny:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := clienttest.New(t, client.EnforcementPoints("audit"))

			if tt.deny {
				_, err := c.AddTemplate(ctx, clienttest.TemplateDeny())
				if err != nil {
					t.Fatal(err)
				}

				_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo"))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				_, err := c.AddTemplate(ctx, clienttest.TemplateAllow())
				if err != nil {
					t.Fatal(err)
				}

				_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindAllow, "foo"))
				if err != nil {
					t.Fatal(err)
				}
			}

			obj := handlertest.Review{Object: handlertest.Object{Name: "bar"}}

			rsps, err := c.Review(ctx, obj, reviews.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			trace := rsps.ByTarget[handlertest.TargetName].Trace
			if trace == nil && tt.tracingEnabled {
				t.Fatal("got nil trace but tracing enabled for Review")
			} else if trace != nil && !tt.tracingEnabled {
				t.Fatalf("got trace but tracing disabled: <<%v>>", *trace)
			}

			_, err = c.AddData(ctx, &obj.Object)
			if err != nil {
				t.Fatal(err)
			}

			td := rsps.TraceDump()
			if tt.tracingEnabled {
				if tt.deny {
					if !strings.Contains(td, "Trace:") || strings.Contains(td, types.TracingDisabledHeader) {
						t.Fatalf("did not find a trace when we were expecting to see one: %s", td)
					}
				} else {
					if strings.Contains(td, types.TracingDisabledHeader) {
						t.Fatalf("tracing is not disabled, we just didn't see a violation: %s", td)
					}
				}
			} else {
				if tt.deny {
					if !strings.Contains(td, types.TracingDisabledHeader) {
						t.Fatalf("tracing is disabled, there shouldn't be a trace: %s", td)
					}
				} else {
					if strings.Contains(td, types.TracingDisabledHeader) {
						t.Fatalf("tracing is disabled, but there were no violations so \"%s\" shouldn't be present: %s", types.TracingDisabledHeader, td)
					}
				}
			}
		})
	}
}

// TestE2E_Tracing_Unmatched tests that non evaluations don't have a misleading
// message: \"Trace: TRACING DISABLED\" trace on a TraceDump().
// A non evaluation can occur when a review doesn't match the constraint's match
// criteria.
func TestE2E_Tracing_Unmatched(t *testing.T) {
	tests := []struct {
		name           string
		tracingEnabled bool
	}{
		{
			name:           "disabled",
			tracingEnabled: false,
		},
		{
			name:           "enabled",
			tracingEnabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := clienttest.New(t, client.Targets([]handler.TargetHandler{&handlertest.Handler{Cache: &handlertest.Cache{}}}...))

			_, err := c.AddData(ctx, &handlertest.Object{Namespace: "ns"})
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(ctx, clienttest.TemplateDeny())
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo", cts.MatchNamespace("aaa")))
			if err != nil {
				t.Fatal(err)
			}

			obj := handlertest.Review{Object: handlertest.Object{Name: "bar", Namespace: "ns"}}

			rsps, err := c.Review(ctx, obj, reviews.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			td := rsps.TraceDump()
			if strings.Contains(td, types.TracingDisabledHeader) {
				t.Fatalf("\"%s\" shouldn't be present: %s", types.TracingDisabledHeader, td)
			}
		})
	}
}

// TestE2E_DriverStats tests that we can turn on and off the Stats() QueryOpt.
func TestE2E_DriverStats(t *testing.T) {
	tests := []struct {
		name         string
		statsEnabled bool
	}{
		{
			name:         "disabled",
			statsEnabled: false,
		},
		{
			name:         "enabled",
			statsEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := clienttest.New(t)

			_, err := c.AddTemplate(ctx, clienttest.TemplateDeny())
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, cts.MakeConstraint(t, clienttest.KindDeny, "foo"))
			if err != nil {
				t.Fatal(err)
			}

			obj := handlertest.Review{Object: handlertest.Object{Name: "bar"}}

			rsps, err := c.Review(ctx, obj, reviews.Stats(tt.statsEnabled))
			if err != nil {
				t.Fatal(err)
			}

			stats := rsps.StatsEntries
			if stats == nil && tt.statsEnabled {
				t.Fatal("got nil stats but stats enabled for Review")
			} else if len(stats) != 0 && !tt.statsEnabled {
				t.Fatal("got stats but stats disabled")
			}
		})
	}
}

func TestE2E_Client_GetDescriptionForStat(t *testing.T) {
	unknownDriverSource := instrumentation.Source{
		Type:  instrumentation.EngineSourceType,
		Value: "unknown_driver",
	}
	unknownSourceType := instrumentation.Source{
		Type:  "unknown_source",
		Value: "unknown_value",
	}
	validSource := instrumentation.RegoSource

	c := clienttest.New(t)
	tests := []struct {
		name            string
		source          instrumentation.Source
		statName        string
		expectedUnknown bool
	}{
		{
			name:            "unknown driver source",
			source:          unknownDriverSource,
			statName:        "some_stat_name",
			expectedUnknown: true,
		},
		{
			name:            "unknown source type",
			source:          unknownSourceType,
			statName:        "some_stat_name",
			expectedUnknown: true,
		},
		{
			name:            "valid source type with unknown stat",
			source:          validSource,
			statName:        "this_stat_does_not_exist",
			expectedUnknown: true,
		},
		{
			name:            "valid source type with known stat",
			source:          validSource,
			statName:        "templateRunTimeNS",
			expectedUnknown: false,
		},
	}

	for _, tc := range tests {
		desc := c.GetDescriptionForStat(tc.source, tc.statName)
		if tc.expectedUnknown && desc != instrumentation.UnknownDescription {
			t.Errorf("expected unknown description for stat %q, got: %q", tc.statName, desc)
		} else if !tc.expectedUnknown && desc == instrumentation.UnknownDescription {
			t.Errorf("expected actual description for stat %q, got: %q", tc.statName, desc)
		}
	}
}
