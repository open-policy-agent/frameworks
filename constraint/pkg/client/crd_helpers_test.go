package client

import (
	"reflect"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

// helpers for creating a ConstraintTemplate for test

type tmplArg func(*v1alpha1.ConstraintTemplate)

func name(name string) tmplArg {
	return func(tmpl *v1alpha1.ConstraintTemplate) {
		tmpl.ObjectMeta.Name = name
	}
}

func crdNames(kind, plural string) tmplArg {
	return func(tmpl *v1alpha1.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Names = apiextensionsv1beta1.CustomResourceDefinitionNames{
			Kind:   kind,
			Plural: plural,
		}
	}
}

func schema(pm propMap) tmplArg {
	p := prop(pm)
	return func(tmpl *v1alpha1.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Validation = &v1alpha1.Validation{}
		tmpl.Spec.CRD.Spec.Validation.OpenAPIV3Schema = &p
	}
}

func targets(ts ...string) tmplArg {
	targets := make(map[string]v1alpha1.Target, len(ts))
	for _, t := range ts {
		targets[t] = v1alpha1.Target{"package hello v{1 == 1}"}
	}

	return func(tmpl *v1alpha1.ConstraintTemplate) {
		tmpl.Spec.Targets = targets
	}
}

func createTemplate(args ...tmplArg) *v1alpha1.ConstraintTemplate {
	tmpl := &v1alpha1.ConstraintTemplate{}
	for _, arg := range args {
		arg(tmpl)
	}
	return tmpl
}

// Minimal implementation of a target handler needed for CRD helpers

type targetHandlerArg func(*testTargetHandler)

func matchSchema(pm propMap) targetHandlerArg {
	return func(h *testTargetHandler) {
		h.matchSchema = prop(pm)
	}
}

var _ MatchSchemaProvider = &testTargetHandler{}

type testTargetHandler struct {
	matchSchema apiextensionsv1beta1.JSONSchemaProps
}

func createTestTargetHandler(args ...targetHandlerArg) MatchSchemaProvider {
	h := &testTargetHandler{}
	for _, arg := range args {
		arg(h)
	}
	return h
}

func (h testTargetHandler) MatchSchema() apiextensionsv1beta1.JSONSchemaProps {
	return h.matchSchema
}

// schema Helpers

type propMap map[string]apiextensionsv1beta1.JSONSchemaProps

// prop currently expects 0 or 1 prop map. More is unsupported.
func prop(pm ...map[string]apiextensionsv1beta1.JSONSchemaProps) apiextensionsv1beta1.JSONSchemaProps {
	if len(pm) == 0 {
		return apiextensionsv1beta1.JSONSchemaProps{}
	}
	return apiextensionsv1beta1.JSONSchemaProps{Properties: pm[0]}
}

func expectedSchema(pm propMap) *apiextensionsv1beta1.JSONSchemaProps {
	p := prop(propMap{"spec": prop(pm)})
	return &p
}

// Tests

type crdTestCase struct {
	Name           string
	Template       *v1alpha1.ConstraintTemplate
	Handler        MatchSchemaProvider
	ExpectedSchema *apiextensionsv1beta1.JSONSchemaProps
	ErrorExpected  bool
}

func TestValidateTemplate(t *testing.T) {
	tests := []crdTestCase{
		{
			Name:          "Valid Template",
			Template:      createTemplate(targets("fooTarget")),
			ErrorExpected: false,
		},
		{
			Name:          "No Targets Fails",
			Template:      createTemplate(),
			ErrorExpected: true,
		},
		{
			Name:          "Two Targets Fails",
			Template:      createTemplate(targets("fooTarget", "barTarget")),
			ErrorExpected: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			err := validateTargets(tc.Template)
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
			Name:           "No Schema",
			Template:       createTemplate(),
			Handler:        createTestTargetHandler(),
			ExpectedSchema: expectedSchema(propMap{"match": prop()}),
		},
		{
			Name:     "Just Match",
			Template: createTemplate(),
			Handler:  createTestTargetHandler(matchSchema(propMap{"labels": prop()})),
			ExpectedSchema: expectedSchema(propMap{
				"match": prop(propMap{
					"labels": prop()})}),
		},
		{
			Name:     "Just Parameters",
			Template: createTemplate(schema(propMap{"test": prop()})),
			Handler:  createTestTargetHandler(),
			ExpectedSchema: expectedSchema(propMap{
				"match": prop(),
				"parameters": prop(propMap{
					"test": prop(),
				}),
			}),
		},
		{
			Name:     "Match and Parameters",
			Template: createTemplate(schema(propMap{"dragon": prop()})),
			Handler:  createTestTargetHandler(matchSchema(propMap{"fire": prop()})),
			ExpectedSchema: expectedSchema(propMap{
				"match": prop(propMap{
					"fire": prop(),
				}),
				"parameters": prop(propMap{
					"dragon": prop(),
				}),
			}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			schema := createSchema(tc.Template, tc.Handler)
			if !reflect.DeepEqual(schema, tc.ExpectedSchema) {
				t.Errorf("createSchema(%#v) = \n%#v; \nwant %#v", tc.Template, *schema, *tc.ExpectedSchema)
			}
		})
	}
}

func TestCRDCreationAndValidation(t *testing.T) {
	tests := []crdTestCase{
		{
			Name: "Most Basic Valid Template",
			Template: createTemplate(
				name("SomeName"),
				crdNames("Horse", "horses"),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Template With Parameter Schema",
			Template: createTemplate(
				name("morehorses"),
				crdNames("Horse", "horses"),
				schema(propMap{
					"coat":  prop(propMap{"color": prop(), "clean": prop()}),
					"speed": prop(),
				}),
			),
			Handler:       createTestTargetHandler(),
			ErrorExpected: false,
		},
		{
			Name: "Template With Parameter and Match Schema",
			Template: createTemplate(
				name("morehorses"),
				crdNames("Horse", "horses"),
				schema(propMap{
					"coat":  prop(propMap{"color": prop(), "clean": prop()}),
					"speed": prop(),
				}),
			),
			Handler: createTestTargetHandler(
				matchSchema(propMap{
					"namespace":     prop(),
					"labelSelector": prop(propMap{"matchLabels": prop()}),
				})),
			ErrorExpected: false,
		},
		{
			Name:          "No Kind Fails",
			Template:      createTemplate(),
			Handler:       createTestTargetHandler(),
			ErrorExpected: true,
		},
	}
	h := newCRDHelper()
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			schema := createSchema(tc.Template, tc.Handler)
			crd := h.createCRD(tc.Template, schema)
			err := h.validateCRD(crd)
			if (err == nil) && tc.ErrorExpected {
				t.Errorf("err = nil; want non-nil")
			}
			if (err != nil) && !tc.ErrorExpected {
				t.Errorf("err = \"%s\"; want nil", err)
			}
		})
	}
}
