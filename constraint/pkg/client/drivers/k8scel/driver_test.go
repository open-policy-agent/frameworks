package k8scel

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/k8scel/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

func makeTemplateWithSource(source *schema.Source, vapGenerationVal *string) *templates.ConstraintTemplate {
	template := &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testkind",
		},
		Spec: templates.ConstraintTemplateSpec{
			Targets: []templates.Target{
				{
					Target: "admission.k8s.io",
					Code: []templates.Code{
						{
							Engine: schema.Name,
							Source: &templates.Anything{
								Value: source.MustToUnstructured(),
							},
						},
					},
				},
			},
		},
	}
	if vapGenerationVal != nil {
		template.SetLabels(map[string]string{
			VAPGenerationLabel: *vapGenerationVal,
		})
	}
	return template
}

func makeTemplate(vapGenerationVal *string) *templates.ConstraintTemplate {
	return makeTemplateWithSource(&schema.Source{
		Validations: []schema.Validation{
			{
				Expression: "1 == 1",
				Message:    "Always true",
			},
		},
	}, vapGenerationVal)
}

func makeConstraint(vapGenerationVal *string) *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{},
	}
	constraint.SetGroupVersionKind(k8sschema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: "TestKind"})
	if err := unstructured.SetNestedField(constraint.Object, "someValue", "spec", "parameters", "testParam"); err != nil {
		panic(err)
	}
	if vapGenerationVal != nil {
		constraint.SetLabels(map[string]string{
			VAPGenerationLabel: *vapGenerationVal,
		})
	}
	return constraint
}

var (
	_ IsAdmissionGetter = &requestWrapper{}
	_ ARGetter          = &requestWrapper{}
)

type requestWrapper struct {
	request     *admissionv1.AdmissionRequest
	isAdmission bool
}

func (rw *requestWrapper) GetAdmissionRequest() *admissionv1.AdmissionRequest {
	return rw.request
}

func (rw *requestWrapper) IsAdmissionRequest() bool {
	return rw.isAdmission
}

func fakeRequest(isAdmission bool) *requestWrapper {
	objStr := `
apiVersion: v1
kind: Pod
metadata:
  "name": "sample-pod"
  "namespace": "random-namespace"
`
	objJSON, err := yaml.YAMLToJSON([]byte(objStr))
	if err != nil {
		panic(err)
	}

	return &requestWrapper{
		isAdmission: isAdmission,
		request: &admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{Raw: objJSON},
		},
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name               string
		template           *templates.ConstraintTemplate
		constraint         *unstructured.Unstructured
		vapDefault         *vapDefault
		isAdmissionRequest bool
		expectedViolations bool
		expectedErr        bool
	}{
		{
			name: "Satisfied constraint",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "sample-pod"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: false,
		},
		{
			name: "Unsatisfied constraint",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: true,
		},
		{
			name: "Filtered constraint",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "must-be-namespace",
						Expression: `object.kind == "Namespace"`,
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: false,
		},
		{
			name: "Unfiltered constraint",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "must-be-pod",
						Expression: `object.kind == "Pod"`,
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: true,
		},
		{
			name: "With User-Defined Variables",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `variables.objName == "sample-pod"`,
						Message:    "unexpected name",
					},
				},
				Variables: []schema.Variable{
					{
						Name:       "objName",
						Expression: `object.metadata.name`,
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: false,
		},
		{
			name: "With Constraint Params",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `variables.params.testParam == "someValue"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			expectedViolations: false,
		},
		// VAP generation
		{
			name: "Unsatisfied constraint, default assume no VAP",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			vapDefault:         ptr.To[vapDefault](VAPDefaultNo),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, default assume VAP",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			vapDefault:         ptr.To[vapDefault](VAPDefaultYes),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, default assume VAP, admission request",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultYes),
			expectedViolations: false,
		},
		{
			name: "Unsatisfied constraint, default assume no VAP, admission request",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(nil),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultNo),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, default assume no VAP, admission request, template override",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, ptr.To[string](string(VAPDefaultYes))),
			constraint:         makeConstraint(nil),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultNo),
			expectedViolations: false,
		},
		{
			name: "Unsatisfied constraint, default assume no VAP, admission request, constraint override",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(ptr.To[string](string(VAPDefaultYes))),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultNo),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, default assume VAP, admission request, constraint override",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, nil),
			constraint:         makeConstraint(ptr.To[string](string(VAPDefaultNo))),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultYes),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, default assume VAP, admission request, constraint template override",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, ptr.To[string](string(VAPDefaultNo))),
			constraint:         makeConstraint(nil),
			isAdmissionRequest: true,
			vapDefault:         ptr.To[vapDefault](VAPDefaultYes),
			expectedViolations: true,
		},
		{
			name: "Unsatisfied constraint, VAP disabled (default == nil), all override",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object.metadata.name == "unrecognizable-name"`,
						Message:    "unexpected name",
					},
				},
			}, ptr.To[string](string(VAPDefaultYes))),
			constraint:         makeConstraint(ptr.To[string](string(VAPDefaultYes))),
			isAdmissionRequest: true,
			expectedViolations: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []Arg{}
			if test.vapDefault != nil {
				args = append(args, VAPGenerationDefault(*test.vapDefault))
			}
			driver, err := New(args...)
			if err != nil {
				t.Fatal(err)
			}
			if err := driver.AddTemplate(context.Background(), test.template); err != nil {
				t.Fatal(err)
			}
			response, err := driver.Query(context.Background(), "", []*unstructured.Unstructured{test.constraint}, fakeRequest(test.isAdmissionRequest))
			if (err != nil) != test.expectedErr {
				t.Errorf("wanted error state to be %v; got %v", test.expectedErr, err != nil)
			}
			if len(response.Results) > 0 != test.expectedViolations {
				t.Errorf("wanted violation presence to be %v; got %v", test.expectedViolations, spew.Sdump(response.Results))
			}
		})
	}
}

func TestAssumeVAPEnforcement(t *testing.T) {
	tests := []struct {
		name       string
		template   *templates.ConstraintTemplate
		vapDefault *vapDefault
		expected   bool
	}{
		{
			name:     "Enabled, default not set => no consideration of VAP enforcement",
			template: makeTemplate(ptr.To[string](string(VAPDefaultYes))),
			expected: false,
		},
		{
			name:       "No stance, default enabled",
			template:   makeTemplate(nil),
			vapDefault: ptr.To[vapDefault](VAPDefaultYes),
			expected:   true,
		},
		{
			name:       "No stance, default disabled",
			template:   makeTemplate(nil),
			vapDefault: ptr.To[vapDefault](VAPDefaultNo),
			expected:   false,
		},
		{
			name:       "Enabled, default 'no'",
			template:   makeTemplate(ptr.To[string](string(VAPDefaultYes))),
			vapDefault: ptr.To[vapDefault](VAPDefaultNo),
			expected:   true,
		},
		{
			name:       "Enabled, default 'yes'",
			template:   makeTemplate(ptr.To[string](string(VAPDefaultYes))),
			vapDefault: ptr.To[vapDefault](VAPDefaultYes),
			expected:   true,
		},
		{
			name:       "Disabled, default 'yes'",
			template:   makeTemplate(ptr.To[string](string(VAPDefaultNo))),
			vapDefault: ptr.To[vapDefault](VAPDefaultYes),
			expected:   false,
		},
		{
			name:       "Disabled, default 'no'",
			template:   makeTemplate(ptr.To[string](string(VAPDefaultNo))),
			vapDefault: ptr.To[vapDefault](VAPDefaultNo),
			expected:   false,
		},
		{
			name:     "Nonsense value, default not set => nonsense ignored",
			template: makeTemplate(ptr.To[string]("catshaveclaws")),
			expected: false,
		},
		{
			name:       "Nonsense value, default set",
			template:   makeTemplate(ptr.To[string]("catshaveclaws")),
			vapDefault: ptr.To[vapDefault](VAPDefaultNo),
			expected:   false,
		},
		{
			name:       "Nonsense value, default set to yes",
			template:   makeTemplate(ptr.To[string]("catshaveclaws")),
			vapDefault: ptr.To[vapDefault](VAPDefaultYes),
			expected:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []Arg{}
			if test.vapDefault != nil {
				args = append(args, VAPGenerationDefault(*test.vapDefault))
			}
			driver, err := New(args...)
			if err != nil {
				t.Fatal(err)
			}
			assumeVAP := driver.assumeVAPEnforcement(test.template)
			if assumeVAP != test.expected {
				t.Errorf("wanted assumeVAP to be %v; got %v", test.expected, assumeVAP)
			}
		})
	}
}
