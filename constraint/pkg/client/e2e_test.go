package client

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8schema "k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	denied    = "DENIED"
	rejection = "REJECTION"
	dryRun    = "DRYRUN"
)

func newConstraintTemplate(name, rego string, libs ...string) *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(name)},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{
				Spec: templates.CRDSpec{
					Names: templates.Names{
						Kind: name,
					},
					Validation: &templates.Validation{
						OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensions.JSONSchemaProps{
								"expected": {Type: "string"},
							},
						},
					},
				},
			},
			Targets: []templates.Target{
				{Target: "test.target", Rego: rego, Libs: libs},
			},
		},
	}
}

func newConstraint(kind, name string, params map[string]string, enforcementAction *string) *unstructured.Unstructured {
	c := &unstructured.Unstructured{}
	c.SetGroupVersionKind(k8schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1alpha1",
		Kind:    kind,
	})
	c.SetName(name)
	if enforcementAction != nil {
		if err := unstructured.SetNestedField(c.Object, *enforcementAction, "spec", "enforcementAction"); err != nil {
			panic(err)
		}
	}
	if err := unstructured.SetNestedStringMap(c.Object, params, "spec", "parameters"); err != nil {
		panic(err)
	}
	return c
}

const (
	// basic deny template.
	denyTemplateRego = `package foo
violation[{"msg": "DENIED", "details": {}}] {
	"always" == "always"
}`

	// basic deny template that uses a lib rule.
	denyTemplateWithLibRego = `package foo

import data.lib.bar

violation[{"msg": "DENIED", "details": {}}] {
  bar.always[x]
	x == "always"
}`

	denyTemplateWithLibLib = `package lib.bar
always[y] {
  y = "always"
}
`
)

var denyAllCases = []struct {
	name string
	rego string
	libs []string
}{{
	name: "No Lib",
	rego: denyTemplateRego,
	libs: []string{},
}, {
	name: "With Lib",
	rego: denyTemplateWithLibRego,
	libs: []string{denyTemplateWithLibLib},
}}

func newTestClient() (*Client, error) {
	d := local.New()
	b, err := NewBackend(Driver(d))
	if err != nil {
		return nil, err
	}
	return b.NewClient(Targets(&handler{}))
}

func TestE2EAddTemplate(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestE2EDenyAll(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				Msg:               denied,
				EnforcementAction: "deny",
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review", "Resource")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2EAudit(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			rsps, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got Audit error: %v, want nil", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				Msg:               denied,
				EnforcementAction: "deny",
				Resource:          obj,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2EAuditX2(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj2); err != nil {
				t.Fatalf("got AddDataX2: %v", err)
			}
			rsps, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got Audit: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				EnforcementAction: "deny",
				Msg:               denied,
			}, {
				Constraint:        cstr,
				EnforcementAction: "deny",
				Msg:               denied,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review", "Resource")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2EAutoreject(t *testing.T) {
	// Autorejection is when we short-circuit the logic which runs Constraints,
	// exiting early in certain circumstances. In this instance, the Constraint
	// specifies a NamespaceSelector, but the client does not have any Namespaces
	// cached. Thus, it is impossible for this Constraint to run properly as it
	// cannot determine if the object's Namespace matches the selector or not.
	//
	// This differs from a normal "DENIED" as we were unable to even run the
	// Constraint.
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", denyTemplateRego))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			goodNamespaceSelectorConstraint := `
{
	"apiVersion": "constraints.gatekeeper.sh/v1alpha1",
	"kind": "Foo",
	"metadata": {
  	"name": "foo-pod"
	},
	"spec": {
  	"match": {
    	"kinds": [
      	{
			"apiGroups": [""],
        	"kinds": ["Pod"]
		}],
		"namespaceSelector": {
			"matchExpressions": [{
	     		"key": "someKey",
				"operator": "Blah",
				"values": ["some value"]
			}]
		}
	},
  	"parameters": {
    	"key": ["value"]
		}
	}
}
`
			u := &unstructured.Unstructured{}
			err = json.Unmarshal([]byte(goodNamespaceSelectorConstraint), u)
			if err != nil {
				t.Fatalf("got Unable to parse constraint JSON: %v", err)
			}

			if _, err := c.AddConstraint(ctx, u); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}

			rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        u,
				EnforcementAction: "deny",
				Msg:               denied,
			}, {
				Constraint:        u,
				EnforcementAction: "deny",
				Msg:               rejection,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review", "Resource")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2ERemoveConstraint(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", denyTemplateRego))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			rsps, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got Audit: %v", err)
			}

			got := rsps.Results()

			want := []*types.Result{{
				Constraint:        cstr,
				EnforcementAction: "deny",
				Msg:               denied,
				Resource:          obj,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review")); diff != "" {
				t.Error(diff)
			}

			if _, err := c.RemoveConstraint(ctx, cstr); err != nil {
				t.Fatalf("got RemoveConstraint: %v", err)
			}
			rsps2, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got AuditX2: %v", err)
			}

			got2 := rsps2.Results()
			var want2 []*types.Result

			if diff := cmp.Diff(want2, got2); diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestE2ERemoveTemplate(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			tmpl := newConstraintTemplate("Foo", denyTemplateRego)
			_, err = c.AddTemplate(ctx, tmpl)
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			rsps, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got Audit: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				EnforcementAction: "deny",
				Msg:               denied,
				Resource:          obj,
			}}
			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review")); diff != "" {
				t.Error(diff)
			}

			if _, err := c.RemoveTemplate(ctx, tmpl); err != nil {
				t.Fatalf("got RemoveTemplate: %v", err)
			}
			rsps2, err := c.Audit(ctx)
			if err != nil {
				t.Fatalf("got AuditX2: %v", err)
			}

			got2 := rsps2.Results()
			var want2 []*types.Result

			if diff := cmp.Diff(want2, got2); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2ETracingOff(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", denyTemplateRego))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			if len(rsps.ByTarget) == 0 {
				t.Fatal("got no results by target, want at least one")
			}
			for key, r := range rsps.ByTarget {
				if r.Trace != nil {
					t.Errorf("got Trace for %q, but want no trace: %v", key, r.Trace)
				}
			}
		})
	}
}

func TestE2ETracingOn(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"}, Tracing(true))
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			if len(rsps.ByTarget) == 0 {
				t.Fatal("got no results by target, want at least one")
			}
			for key, r := range rsps.ByTarget {
				if r.Trace == nil {
					t.Errorf("got no Trace for: %q, but want trace", key)
				}
			}
		})
	}
}

func TestE2EAuditTracingOn(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj2); err != nil {
				t.Fatalf("got AddDataX2: %v", err)
			}
			rsps, err := c.Audit(ctx, Tracing(true))
			if err != nil {
				t.Fatalf("got Audit: %v", err)
			}

			if len(rsps.ByTarget) == 0 {
				t.Fatal("got no results by target, want at least one")
			}
			for key, r := range rsps.ByTarget {
				if r.Trace == nil {
					t.Errorf("got no Trace for: %q, but want trace", key)
				}
			}
		})
	}
}

func TestE2EAuditTracingOff(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", tc.rego, tc.libs...))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", nil, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			obj := &targetData{Name: "Sara", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj); err != nil {
				t.Fatalf("got AddData: %v", err)
			}
			obj2 := &targetData{Name: "Max", ForConstraint: "Foo"}
			if _, err := c.AddData(ctx, obj2); err != nil {
				t.Fatalf("got AddDataX2: %v", err)
			}
			rsps, err := c.Audit(ctx, Tracing(false))
			if err != nil {
				t.Fatalf("got Audit: %v", err)
			}

			if len(rsps.ByTarget) == 0 {
				t.Fatal("got no results by target, want at least one")
			}
			for key, r := range rsps.ByTarget {
				if r.Trace != nil {
					t.Errorf("got Trace for %q, but want no trace: %v", key, r.Trace)
				}
			}
		})
	}
}

func TestE2EDryrunAll(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DRYRUN", "details": {}}] {
	"always" == "always"
}`))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			testEnforcementAction := "dryrun"
			cstr := newConstraint("Foo", "ph", nil, &testEnforcementAction)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				EnforcementAction: testEnforcementAction,
				Msg:               dryRun,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review", "Resource")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestE2EDenyByParameter(t *testing.T) {
	for _, tc := range denyAllCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newTestClient()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			_, err = c.AddTemplate(ctx, newConstraintTemplate("Foo", `package foo
violation[{"msg": "DENIED", "details": {}}] {
	input.parameters.name == input.review.Name
}`))
			if err != nil {
				t.Fatalf("got AddTemplate: %v", err)
			}
			cstr := newConstraint("Foo", "ph", map[string]string{"name": "deny_me"}, nil)
			if _, err := c.AddConstraint(ctx, cstr); err != nil {
				t.Fatalf("got AddConstraint: %v", err)
			}
			rsps, err := c.Review(ctx, targetData{Name: "deny_me", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			got := rsps.Results()
			want := []*types.Result{{
				Constraint:        cstr,
				EnforcementAction: "deny",
				Msg:               denied,
			}}

			if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(types.Result{},
				"Metadata", "Review", "Resource")); diff != "" {
				t.Error(diff)
			}

			rsps, err = c.Review(ctx, targetData{Name: "Sara", ForConstraint: "Foo"})
			if err != nil {
				t.Fatalf("got Review: %v", err)
			}

			if len(rsps.ByTarget) == 0 {
				t.Fatal("got no responses")
			}
			results := rsps.Results()
			if len(results) != 0 {
				t.Fatalf("got results, want none: %v", results)
			}
		})
	}
}
