package client_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/topdown/print"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

func TestClient_Review(t *testing.T) {
	tests := []struct {
		name        string
		namespaces  []string
		targets     []handler.TargetHandler
		templates   []*templates.ConstraintTemplate
		constraints []*unstructured.Unstructured
		inventory   []*handlertest.Object
		toReview    interface{}

		wantResults []*types.Result
		wantErr     error
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
					Name: pointer.String("foo1"),
				},
				&handlertest.Handler{
					Name: pointer.String("foo2"),
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c := clienttest.New(t, client.Targets(tt.targets...))

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

			responses, err := c.Review(ctx, tt.toReview)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			results := responses.Results()

			diffOpt := cmpopts.IgnoreFields(types.Result{}, "Metadata", "EvaluationMeta")
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
		EnforcementAction: constraints.EnforcementActionDeny,
		Constraint: cts.MakeConstraint(t, clienttest.KindCheckData, "constraint",
			cts.WantData("bar")),
		Metadata: map[string]interface{}{"details": map[string]interface{}{"got": "qux"}},
	}}

	results := responses.Results()

	diffOpt := cmpopts.IgnoreFields(types.Result{}, "EvaluationMeta")
	if diff := cmp.Diff(want, results, diffOpt); diff != "" {
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
				EnforcementAction: constraints.EnforcementActionDeny,
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
				EnforcementAction: constraints.EnforcementActionDeny,
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

			c, err := client.NewClient(client.Targets(&handlertest.Handler{}), client.Driver(d))
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
				cmpopts.IgnoreFields(types.Result{}, "Metadata", "EvaluationMeta")); diff != "" {
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
		EnforcementAction: constraints.EnforcementActionDeny,
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Metadata", "EvaluationMeta")); diff != "" {
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
		EnforcementAction: constraints.EnforcementActionDeny,
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Metadata", "EvaluationMeta")); diff != "" {
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

func TestE2E_Tracing(t *testing.T) {
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

			rsps, err := c.Review(ctx, obj, drivers.Tracing(tt.tracingEnabled))
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
		})
	}
}

// TestE2E_Review_RegoEvaluationMeta tests that we can get stats out of evaluated constraints.
func TestE2E_Review_RegoEvaluationMeta(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)
	ct := clienttest.TemplateCheckData()
	_, err := c.AddTemplate(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}
	numConstrains := 3

	for i := 1; i < numConstrains+1; i++ {
		name := "constraint-" + strconv.Itoa(i)
		constraint := cts.MakeConstraint(t, clienttest.KindCheckData, name, cts.WantData("bar"))
		_, err = c.AddConstraint(ctx, constraint)
		if err != nil {
			t.Fatal(err)
		}
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

	results := responses.Results()

	// for each result check that we have the constraintCount == 3 and a positive templateRunTime
	for _, result := range results {
		stats, ok := result.EvaluationMeta.(rego.EvaluationMeta)
		if !ok {
			t.Fatalf("could not type convert to RegoEvaluationMeta")
		}

		if stats.TemplateRunTime == 0 {
			t.Fatalf("expected %v's value to be positive was zero", "TemplateRunTime")
		}

		if stats.ConstraintCount != uint(numConstrains) {
			t.Fatalf("expected %v constraint count, got %v", numConstrains, "ConstraintCount")
		}
	}
}
