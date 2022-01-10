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
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestClient_Review(t *testing.T) {
	tts := []struct {
		name        string
		handler     client.TargetHandler
		templates   []*templates.ConstraintTemplate
		constraints []*unstructured.Unstructured
		toReview    interface{}

		wantResults []*types.Result
		wantErr     error
	}{
		{
			name:    "empty client",
			handler: &clienttest.Handler{},
			toReview: clienttest.Review{
				Object: clienttest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "deny missing Constraint",
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "deny all",
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDeny(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindDeny, "constraint"),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
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
			name:    "deny all library",
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateDenyImport(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindDenyImport, "constraint"),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
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
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateAllow(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindAllow, "constraint"),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "check data allow",
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
					Name: "foo",
					Data: "bar",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
		{
			name:    "check data deny",
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
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
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar"), clienttest.EnableAutoreject),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
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
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.MatchNamespace("billing")),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
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
			handler: &clienttest.Handler{},
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			constraints: []*unstructured.Unstructured{
				clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint",
					clienttest.WantData("bar"), clienttest.MatchNamespace("billing")),
			},
			toReview: clienttest.Review{
				Object: clienttest.Object{
					Name:      "foo",
					Namespace: "shipping",
					Data:      "qux",
				},
				Autoreject: false,
			},
			wantResults: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(tt.handler))
			if err != nil {
				t.Fatal(err)
			}

			for _, template := range tt.templates {
				_, err = c.AddTemplate(template)
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, constraint := range tt.constraints {
				_, err = c.AddConstraint(ctx, constraint)
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

	d := local.New()

	b, err := client.NewBackend(client.Driver(d))
	if err != nil {
		t.Fatal(err)
	}

	c, err := b.NewClient(client.Targets(&clienttest.Handler{}))
	if err != nil {
		t.Fatal(err)
	}

	template := clienttest.TemplateCheckData()
	_, err = c.AddTemplate(template)
	if err != nil {
		t.Fatal(err)
	}

	constraint := clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar"))
	_, err = c.AddConstraint(ctx, constraint)
	if err != nil {
		t.Fatal(err)
	}

	review := clienttest.Review{
		Object: clienttest.Object{
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
		objects     []*clienttest.Object
		want        []*types.Result
	}{
		{
			name:        "empty client returns empty audit",
			templates:   nil,
			constraints: nil,
			objects:     nil,
		},
		{
			name: "no template returns empty audit",
			templates: []*templates.ConstraintTemplate{
				clienttest.TemplateCheckData(),
			},
			objects: []*clienttest.Object{
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
			objects: []*clienttest.Object{
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
			objects: []*clienttest.Object{
				{Name: "foo", Data: "qux"},
				{Name: "foo2", Namespace: "bar", Data: "zab"},
			},
			want: []*types.Result{
				{
					Msg:        "got qux but want bar for data",
					Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
					Resource: &clienttest.Review{
						Object: clienttest.Object{Name: "foo", Data: "qux"},
					},
					EnforcementAction: "deny",
				},
				{
					Msg:        "got zab but want bar for data",
					Constraint: clienttest.MakeConstraint(t, clienttest.KindCheckData, "constraint", clienttest.WantData("bar")),
					Resource: &clienttest.Review{
						Object: clienttest.Object{Name: "foo2", Namespace: "bar", Data: "zab"},
					},
					EnforcementAction: "deny",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			d := local.New()

			b, err := client.NewBackend(client.Driver(d))
			if err != nil {
				t.Fatal(err)
			}

			c, err := b.NewClient(client.Targets(&clienttest.Handler{}))
			if err != nil {
				t.Fatal(err)
			}

			for _, template := range tt.templates {
				_, err = c.AddTemplate(template)
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, constraint := range tt.constraints {
				_, err = c.AddConstraint(ctx, constraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			for _, object := range tt.objects {
				_, err = c.AddData(ctx, object)
				if err != nil {
					t.Fatal(err)
				}
			}

			responses, err := c.Audit(ctx)
			if err != nil {
				t.Fatal(err)
			}

			results := responses.Results()

			if diff := cmp.Diff(tt.want, results, cmpopts.IgnoreFields(types.Result{}, "Review", "Metadata")); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
