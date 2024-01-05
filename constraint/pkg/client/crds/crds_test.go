package crds_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
)

// Minimal implementation of a target handler needed for CRD helpers

type targetHandlerArg func(*testTargetHandler)

func matchSchema(pm cts.PropMap) targetHandlerArg {
	return func(h *testTargetHandler) {
		h.matchSchema = cts.Prop(pm)
	}
}

var _ crds.MatchSchemaProvider = &testTargetHandler{}

type testTargetHandler struct {
	matchSchema apiextensions.JSONSchemaProps
}

func createTestTargetHandler(args ...targetHandlerArg) crds.MatchSchemaProvider {
	h := &testTargetHandler{}

	// The default matchSchema is empty, and thus lacks type information
	h.matchSchema.XPreserveUnknownFields = ptr.To[bool](true)

	for _, arg := range args {
		arg(h)
	}
	return h
}

func (h *testTargetHandler) MatchSchema() apiextensions.JSONSchemaProps {
	return h.matchSchema
}

// schema Helpers

// Custom Resource Helpers

type customResourceArg func(u *unstructured.Unstructured)

func gvk(group, version, kind string) customResourceArg {
	return func(u *unstructured.Unstructured) {
		u.SetGroupVersionKind(k8schema.GroupVersionKind{Group: group, Version: version, Kind: kind})
	}
}

func kind(kind string) customResourceArg {
	return gvk(constraints.Group, "v1beta1", kind)
}

func params(s string) customResourceArg {
	p := map[string]interface{}{}
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		panic(fmt.Sprintf("bad JSON in test: %s: %s", s, err))
	}
	return func(u *unstructured.Unstructured) {
		if err := unstructured.SetNestedField(u.Object, p, "spec", "parameters"); err != nil {
			panic(err)
		}
	}
}

func match(s string) customResourceArg {
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		panic(fmt.Sprintf("bad JSON in test: %s: %s", s, err))
	}
	return func(u *unstructured.Unstructured) {
		if err := unstructured.SetNestedField(u.Object, m, "spec", "match"); err != nil {
			panic(err)
		}
	}
}

func crName(name string) customResourceArg {
	return func(u *unstructured.Unstructured) {
		u.SetName(name)
	}
}

func enforcementAction(s string) customResourceArg {
	return func(u *unstructured.Unstructured) {
		if err := unstructured.SetNestedField(u.Object, s, "spec", "enforcementAction"); err != nil {
			panic(err)
		}
	}
}

func createCR(args ...customResourceArg) *unstructured.Unstructured {
	cr := &unstructured.Unstructured{}
	for _, arg := range args {
		arg(cr)
	}
	return cr
}

// Tests

type crdTestCase struct {
	Name           string
	Template       *templates.ConstraintTemplate
	Handler        crds.MatchSchemaProvider
	CR             *unstructured.Unstructured
	ExpectedSchema *apiextensions.JSONSchemaProps
	ErrorExpected  bool
}

func TestValidateTemplate(t *testing.T) {
	tests := []crdTestCase{
		{
			Name:          "Valid Template",
			Template:      cts.New(cts.OptTargets(cts.Target("fooTarget", cts.ModuleDeny))),
			ErrorExpected: false,
		},
		{
			Name:          "No Targets Fails",
			Template:      cts.New(cts.OptTargets()),
			ErrorExpected: true,
		},
		{
			Name: "Two Targets Fails",
			Template: cts.New(cts.OptTargets(
				cts.Target("fooTarget", cts.ModuleDeny),
				cts.Target("barTarget", cts.ModuleDeny))),
			ErrorExpected: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			err := crds.ValidateTargets(tc.Template)
			if (err == nil) && tc.ErrorExpected {
				t.Errorf("err = nil; want non-nil")
			}

			if (err != nil) && !tc.ErrorExpected {
				t.Errorf("err = \"%s\"; want nil", err)
			}
		})
	}
}

func TestCreateSchema(t *testing.T) {
	tests := []crdTestCase{
		{
			Name:     "Just EnforcementAction",
			Template: cts.New(),
			Handler:  createTestTargetHandler(),
			ExpectedSchema: cts.ExpectedSchema(cts.PropMap{
				"match":      cts.PropUnstructured(),
				"parameters": cts.PropTyped("object"),
			}),
		},
		{
			Name:     "Add to the match schema",
			Template: cts.New(),
			Handler:  createTestTargetHandler(matchSchema(cts.PropMap{"labels": cts.PropUnstructured()})),
			ExpectedSchema: cts.ExpectedSchema(cts.PropMap{
				"match": cts.Prop(cts.PropMap{
					"labels": cts.PropUnstructured(),
				}),
				"parameters": cts.PropTyped("object"),
			}),
		},
		{
			Name:     "Add to the parameters schema",
			Template: cts.New(cts.OptCRDSchema(cts.PropMap{"test": cts.PropUnstructured()})),
			Handler:  createTestTargetHandler(),
			ExpectedSchema: cts.ExpectedSchema(cts.PropMap{
				"match": cts.PropUnstructured(),
				"parameters": cts.Prop(cts.PropMap{
					"test": cts.PropUnstructured(),
				}),
			}),
		},
		{
			Name:     "Add to match and parameters schemas",
			Template: cts.New(cts.OptCRDSchema(cts.PropMap{"dragon": cts.PropUnstructured()})),
			Handler:  createTestTargetHandler(matchSchema(cts.PropMap{"fire": cts.PropUnstructured()})),
			ExpectedSchema: cts.ExpectedSchema(cts.PropMap{
				"match": cts.Prop(cts.PropMap{
					"fire": cts.PropUnstructured(),
				}),
				"parameters": cts.Prop(cts.PropMap{
					"dragon": cts.PropUnstructured(),
				}),
			}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			schema := crds.CreateSchema(tc.Template, tc.Handler)

			if !reflect.DeepEqual(schema, tc.ExpectedSchema) {
				diff := cmp.Diff(schema.Properties["spec"], tc.ExpectedSchema.Properties["spec"])
				t.Errorf("Unexpected schema output.  Diff: %v", diff)
			}
		})
	}
}

func TestCRDCreationAndValidation(t *testing.T) {
	tests := []crdTestCase{
		{
			Name: "Most Basic Valid Template",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Most Basic Valid Template With Labels",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptLabels(map[string]string{"horse": "smiley"}),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Validtemplate with trying to override system label",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptLabels(map[string]string{"gatekeeper.sh/constraint": "no"}),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Template With Parameter Schema",
			Template: cts.New(
				cts.OptName("morehorses"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{
					"coat":  cts.Prop(cts.PropMap{"color": cts.PropUnstructured(), "clean": cts.PropUnstructured()}),
					"speed": cts.PropUnstructured(),
				}),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Template With Parameter and Match Schema",
			Template: cts.New(
				cts.OptName("morehorses"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{
					"coat":  cts.Prop(cts.PropMap{"color": cts.PropUnstructured(), "clean": cts.PropUnstructured()}),
					"speed": cts.PropUnstructured(),
				}),
			),
			Handler: createTestTargetHandler(
				matchSchema(cts.PropMap{
					"namespace":     cts.PropUnstructured(),
					"labelSelector": cts.Prop(cts.PropMap{"matchLabels": cts.PropUnstructured()}),
				})),
			ErrorExpected: false,
		},
		{
			Name:          "No CRD Names Fails",
			Template:      cts.New(cts.OptCRDNames("")),
			Handler:       createTestTargetHandler(),
			ErrorExpected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			schema := crds.CreateSchema(tc.Template, tc.Handler)
			crd, err := crds.CreateCRD(tc.Template, schema)

			if err != nil {
				t.Errorf("err = %v; want nil", err)
			} else if val, ok := crd.ObjectMeta.Labels["gatekeeper.sh/constraint"]; !ok || val != "yes" {
				t.Errorf("Wanted label gatekeeper.sh/constraint as yes. but obtained %s", val)
			} else if crd.Spec.Names.Categories[0] != "constraint" ||
				crd.Spec.Names.Categories[1] != "constraints" {
				t.Errorf("Generated CRDs are expected to belong to constraint / constraints categories")
			}

			err = crds.ValidateCRD(ctx, crd)
			if (err == nil) && tc.ErrorExpected {
				t.Errorf("err = nil; want non-nil")
			}
			if (err != nil) && !tc.ErrorExpected {
				t.Errorf("err = \"%s\"; want nil", err)
			}
		})
	}
}

func TestCRValidation(t *testing.T) {
	tests := []crdTestCase{
		{
			Name: "Empty Schema and CR",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(crName("mycr"), kind("Horse")),
			ErrorExpected: false,
		},
		{
			Name: "Correct Prop Type",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{"fast": cts.PropTyped("boolean")}),
			),
			Handler: createTestTargetHandler(),
			CR: createCR(
				crName("mycr"),
				kind("Horse"),
				params(`{"fast": true}`),
			),
			ErrorExpected: false,
		},
		{
			Name: "Correct Prop And Match Type",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{"fast": cts.PropTyped("boolean")}),
			),
			Handler: createTestTargetHandler(
				matchSchema(cts.PropMap{"heavierThanLbs": cts.PropTyped("number")}),
			),
			CR: createCR(
				crName("mycr"),
				kind("Horse"),
				params(`{"fast": true}`),
				match(`{"heavierThanLbs": 100}`),
			),
			ErrorExpected: false,
		},
		{
			Name: "No name",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(kind("Horse")),
			ErrorExpected: true,
		},
		{
			Name: "Wrong Kind",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(crName("mycr"), kind("Cat")),
			ErrorExpected: true,
		},
		{
			Name: "Wrong Version",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(crName("mycr"), gvk(constraints.Group, "badversion", "Horse")),
			ErrorExpected: true,
		},
		{
			Name: "Wrong Group",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(crName("mycr"), gvk("badgroup", "v1alpha1", "Horse")),
			ErrorExpected: true,
		},
		{
			Name: "Wrong Prop Type",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{"fast": cts.PropTyped("boolean")}),
			),
			Handler: createTestTargetHandler(),
			CR: createCR(
				crName("mycr"),
				kind("Horse"),
				params(`{"fast": "the fastest"}`),
			),
			ErrorExpected: true,
		},
		{
			Name: "Wrong Prop And Match Type",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
				cts.OptCRDSchema(cts.PropMap{"fast": cts.PropTyped("boolean")}),
			),
			Handler: createTestTargetHandler(
				matchSchema(cts.PropMap{"heavierThanLbs": cts.PropTyped("number")}),
			),
			CR: createCR(
				crName("mycr"),
				kind("Horse"),
				params(`{"fast": true}`),
				match(`{"heavierThanLbs": "one hundred"}`),
			),
			ErrorExpected: true,
		},
		{
			Name: "None default EnforcementAction",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler:       createTestTargetHandler(),
			CR:            createCR(crName("mycr"), kind("Horse"), enforcementAction("dryrun")),
			ErrorExpected: false,
		},
		{
			Name: "unknown fields",
			Template: cts.New(
				cts.OptName("SomeName"),
				cts.OptCRDNames("Horse"),
			),
			Handler: createTestTargetHandler(),
			CR: func() *unstructured.Unstructured {
				cr := createCR(crName("mycr"), kind("Horse"), params(`{"fast": true}`))
				err := unstructured.SetNestedField(cr.Object, make(map[string]interface{}), "spec", "randomField")
				if err != nil {
					t.Fatal(err)
				}
				return cr
			}(),
			ErrorExpected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()
			schema := crds.CreateSchema(tc.Template, tc.Handler)
			crd, err := crds.CreateCRD(tc.Template, schema)
			if err != nil {
				t.Errorf("err = %v; want nil", err)
			}

			if err := crds.ValidateCRD(ctx, crd); err != nil {
				t.Errorf("Bad test setup: Bad CRD: %s", err)
			}

			err = crds.ValidateCR(tc.CR, crd)
			if (err == nil) && tc.ErrorExpected {
				t.Errorf("err = nil; want non-nil")
			}

			if (err != nil) && !tc.ErrorExpected {
				t.Errorf("err = \"%s\"; want nil", err)
			}
		})
	}
}
