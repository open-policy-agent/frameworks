package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/topdown/print"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestClient_Review(t *testing.T) {
	tests := []struct {
		name        string
		handler     handler.TargetHandler
		templates   []*templates.ConstraintTemplate
		constraints []*unstructured.Unstructured
		toReview    interface{}

		wantResults []*types.Result
		wantErr     error
	}{
		{
			name:    "empty client",
			handler: &handlertest.Handler{},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "deny missing Constraint",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "deny all",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: []*types.Result{{
				Msg:               "denied",
				EnforcementAction: "deny",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			}},
		},
		{
			name:    "deny all dryrun",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindDeny, "constraint", clienttest.EnforcementAction("dryrun")),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: []*types.Result{{
				Msg:               "denied",
				EnforcementAction: "dryrun",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "constraint", clienttest.EnforcementAction("dryrun")),
			}},
		},
		{
			name:    "deny all library",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDenyImport(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindDenyImport, "constraint"),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: []*types.Result{{
				Msg:               "denied with library",
				EnforcementAction: "deny",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindDenyImport, "constraint"),
			}},
		},
		{
			name:    "allow all",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateAllow(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindAllow, "constraint"),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "check data allow",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "check data deny",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "qux",
				},
				Autoreject: false,
			},
			wantResults: []*types.Result{{
				Msg:               "got qux but want bar for data",
				EnforcementAction: "deny",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			}},
		},
		{
			name:    "autoreject",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar"), clienttest.EnableAutoreject),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: true,
			},
			wantResults: []*types.Result{{
				Msg:               "autoreject",
				EnforcementAction: "deny",
				Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.EnableAutoreject),
			}},
		},
		{
			name:    "namespace matches",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.MatchNamespace("billing")),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name:      "foo",
					Namespace: "billing",
					Data:      "qux",
				},
				Autoreject: false,
			},
			wantResults: []*types.Result{{
				Msg:               "got qux but want bar for data",
				EnforcementAction: "deny",
				Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.MatchNamespace("billing")),
			}},
		},
		{
			name:    "namespace does not match",
			handler: &handlertest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.MatchNamespace("billing")),
			},
			toReview: handlertest.Review{
				Object: handlertest.Object{
					Name:      "foo",
					Namespace: "shipping",
					Data:      "qux",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c := clienttest.New(t)

			for _, ct := range tt.templates {
				_, err := c.AddTemplate(ct)
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

			responses, err := c.Review(ctx, tt.toReview)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			results := responses.Results()

			diffOpt := cmpopts.IgnoreFields(types.Result{}, "Metadata", "Review", "Resource")
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
	_, err := c.AddTemplate(ct)
	if err != nil {
		t.Fatal(err)
	}

	constraint := clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar"))
	_, err = c.AddConstraint(ctx, constraint)
	if err != nil {
		t.Fatal(err)
	}

	review := handlertest.Review{
		Object: handlertest.Object{
			Name: "foo",
			Data: "qux",
		},
		Autoreject: false,
	}

	responses, err := c.Review(ctx, review)
	if err != nil {
		t.Fatal(err)
	}

	want := []*types.Result{{
		Msg:               "got qux but want bar for data",
		EnforcementAction: "deny",
		Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
			clienttest.WantData("bar")),
		Metadata: map[string]interface{}{"details": map[string]interface{}{"got": "qux"}},
	}}

	results := responses.Results()

	diffOpt := cmpopts.IgnoreFields(types.Result{}, "Review", "Resource")
	if diff := cmp.Diff(want, results, diffOpt); diff != "" {
		t.Error(diff)
	}
}

func TestClient_Audit(t *testing.T) {
	tests := []struct {
		name        string
		templates   []*templates.ConstraintTemplate
		constraints []*unstructured.Unstructured
		objects     []*handlertest.Object
		want        []*types.Result
	}{
		{
			name:        "empty client returns empty audit",
			templates:   nil,
			constraints: nil,
			objects:     nil,
		},
		{
			name:        "no template returns empty audit",
			templates:   nil,
			constraints: nil,
			objects: []*handlertest.Object{
				{Name: "foo", Data: "qux"},
			},
			want: nil,
		},
		{
			name: "no constraint returns empty audit",
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: nil,
			objects: []*handlertest.Object{
				{Name: "foo", Data: "qux"},
			},
			want: nil,
		},
		{
			name: "no objects returns empty audit",
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			objects: nil,
			want:    nil,
		},
		{
			name: "valid objects returns empty audit",
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			objects: []*handlertest.Object{
				{Name: "foo", Data: "bar"},
				{Name: "foo2", Namespace: "bar", Data: "bar"},
			},
			want: nil,
		},
		{
			name: "failing object returns responses",
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			objects: []*handlertest.Object{
				{Name: "foo", Data: "qux"},
				{Name: "foo2", Namespace: "bar", Data: "zab"},
			},
			want: []*types.Result{
				{
					Msg:        "got qux but want bar for data",
					Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
					Resource: &handlertest.Review{
						Object: handlertest.Object{Name: "foo", Data: "qux"},
					},
					EnforcementAction: "deny",
				},
				{
					Msg:        "got zab but want bar for data",
					Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
					Resource: &handlertest.Review{
						Object: handlertest.Object{Name: "foo2", Namespace: "bar", Data: "zab"},
					},
					EnforcementAction: "deny",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c := clienttest.New(t)

			for _, ct := range tt.templates {
				_, err := c.AddTemplate(ct)
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

			for _, object := range tt.objects {
				_, err := c.AddData(ctx, object)
				if err != nil {
					t.Fatal(err)
				}
			}

			responses, err := c.Audit(ctx)
			if err != nil {
				t.Fatal(err)
			}

			results := responses.Results()

			if diff := cmp.Diff(tt.want, results,
				cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata")); diff != "" {
				t.Fatal(diff)
			}
		})
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
				Msg:               "denied",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint"),
				Resource:          &handlertest.Review{Object: handlertest.Object{Name: "hanna"}},
				EnforcementAction: "deny",
			},
		},
		wantPrint: []string{"denied!"},
	}, {
		name:         "Print disabled",
		printEnabled: false,
		wantResults: []*types.Result{
			{
				Msg:               "denied",
				Constraint:        clienttest.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint"),
				Resource:          &handlertest.Review{Object: handlertest.Object{Name: "hanna"}},
				EnforcementAction: "deny",
			},
		},
		wantPrint: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			var printed []string
			printHook := appendingPrintHook{printed: &printed}

			d := local.New(local.PrintEnabled(tc.printEnabled), local.PrintHook(printHook))
			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(&handlertest.Handler{}))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddTemplate(clienttest.TemplateDenyPrint())
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}

			cstr := clienttest.MakeConstraint(t, clienttest.KindDenyPrint, "denyprint")
			if _, err = c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}

			rsps, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "hanna"}})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			results := rsps.Results()
			if diff := cmp.Diff(tc.wantResults, results,
				cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata")); diff != "" {
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

	_, err := c.AddTemplate(clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Msg:               "denied",
		Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: "deny",
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}

	_, err = c.RemoveConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses2, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got2 := responses2.Results()
	var want2 []*types.Result

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}
}

func TestE2E_RemoveTemplate(t *testing.T) {
	ctx := context.Background()
	c := clienttest.New(t)

	_, err := c.AddTemplate(clienttest.TemplateDeny())
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
	if err != nil {
		t.Fatal(err)
	}

	responses, err := c.Review(ctx, handlertest.Review{Object: handlertest.Object{Name: "bar"}})
	if err != nil {
		t.Fatal(err)
	}

	got := responses.Results()
	want := []*types.Result{{
		Msg:               "denied",
		Constraint:        clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"),
		EnforcementAction: "deny",
	}}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
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

	if diff := cmp.Diff(want2, got2, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata", "Resource")); diff != "" {
		t.Fatal(diff)
	}
}

func TestE2E_Review_Tracing(t *testing.T) {
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

			_, err := c.AddTemplate(clienttest.TemplateDeny())
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, clienttest.MakeConstraint(t, clienttest.KindDeny, "foo"))
			if err != nil {
				t.Fatal(err)
			}

			obj := handlertest.Review{Object: handlertest.Object{Name: "bar"}}

			rsps, err := c.Review(ctx, obj, client.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			trace := rsps.ByTarget[handlertest.HandlerName].Trace
			if trace == nil && tt.tracingEnabled {
				t.Fatal("got nil trace but tracing enabled")
			} else if trace != nil && !tt.tracingEnabled {
				t.Fatalf("got trace but tracing disabled: %v", *trace)
			}

			_, err = c.AddData(ctx, &obj.Object)
			if err != nil {
				t.Fatal(err)
			}

			rsps2, err := c.Audit(ctx, client.Tracing(tt.tracingEnabled))
			if err != nil {
				t.Fatal(err)
			}

			trace2 := rsps2.ByTarget[handlertest.HandlerName].Trace
			if trace2 == nil && tt.tracingEnabled {
				t.Fatal("got nil trace but tracing enabled")
			} else if trace2 != nil && !tt.tracingEnabled {
				t.Fatalf("got trace but tracing disabled: %v", *trace)
			}
		})
	}
}
