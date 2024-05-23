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

func makeTemplateWithSource(source *schema.Source, vapGenerationVal *bool) *templates.ConstraintTemplate {
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
							Engine:      schema.Name,
							GenerateVAP: vapGenerationVal,
							Source: &templates.Anything{
								Value: source.MustToUnstructured(),
							},
						},
					},
				},
			},
		},
	}
	return template
}

func makeTemplate(vapGenerationVal *bool) *templates.ConstraintTemplate {
	return makeTemplateWithSource(&schema.Source{
		Validations: []schema.Validation{
			{
				Expression: "1 == 1",
				Message:    "Always true",
			},
		},
	}, vapGenerationVal)
}

func makeConstraint() *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{},
	}
	constraint.SetGroupVersionKind(k8sschema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: "TestKind"})
	if err := unstructured.SetNestedField(constraint.Object, "someValue", "spec", "parameters", "testParam"); err != nil {
		panic(err)
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
		vapDefault         bool
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
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
			constraint:         makeConstraint(),
			vapDefault:         false,
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
			constraint:         makeConstraint(),
			vapDefault:         true,
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
			constraint:         makeConstraint(),
			isAdmissionRequest: true,
			vapDefault:         true,
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
			constraint:         makeConstraint(),
			isAdmissionRequest: true,
			vapDefault:         false,
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
			}, ptr.To[bool](true)),
			constraint:         makeConstraint(),
			isAdmissionRequest: true,
			vapDefault:         false,
			expectedViolations: false,
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
			}, ptr.To[bool](false)),
			constraint:         makeConstraint(),
			isAdmissionRequest: true,
			vapDefault:         true,
			expectedViolations: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []Arg{}
			args = append(args, VAPGenerationDefault(test.vapDefault))
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
		vapDefault bool
		expected   bool
	}{
		{
			name:       "No stance, default enabled",
			template:   makeTemplate(nil),
			vapDefault: true,
			expected:   true,
		},
		{
			name:       "No stance, default disabled",
			template:   makeTemplate(nil),
			vapDefault: false,
			expected:   false,
		},
		{
			name:       "Enabled, default 'no'",
			template:   makeTemplate(ptr.To[bool](true)),
			vapDefault: false,
			expected:   true,
		},
		{
			name:       "Enabled, default 'yes'",
			template:   makeTemplate(ptr.To[bool](true)),
			vapDefault: true,
			expected:   true,
		},
		{
			name:       "Disabled, default 'yes'",
			template:   makeTemplate(ptr.To[bool](false)),
			vapDefault: true,
			expected:   false,
		},
		{
			name:       "Disabled, default 'no'",
			template:   makeTemplate(ptr.To[bool](false)),
			vapDefault: false,
			expected:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []Arg{}
			args = append(args, VAPGenerationDefault(test.vapDefault))
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
