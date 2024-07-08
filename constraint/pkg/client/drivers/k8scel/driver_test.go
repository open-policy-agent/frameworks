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
	"sigs.k8s.io/yaml"
)

func makeTemplateWithSource(source *schema.Source) *templates.ConstraintTemplate {
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
	return template
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

func fakeRequest() *requestWrapper {
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
		expectedViolations bool
		expectedErr        bool
		isDelete           bool
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
			}),
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
			}),
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
			}),
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
			}),
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
			}),
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
			}),
			constraint:         makeConstraint(),
			expectedViolations: false,
		},
		{
			name: "Object Not Set for Delete",
			template: makeTemplateWithSource(&schema.Source{
				Validations: []schema.Validation{
					{
						Expression: `object == null`,
						Message:    "object should be null",
					},
				},
			}),
			constraint:         makeConstraint(),
			expectedViolations: false,
			isDelete:           true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []Arg{}
			driver, err := New(args...)
			if err != nil {
				t.Fatal(err)
			}
			if err := driver.AddTemplate(context.Background(), test.template); err != nil {
				t.Fatal(err)
			}
			req := fakeRequest()
			if test.isDelete {
				req.request.Operation = admissionv1.Delete
			}
			response, err := driver.Query(context.Background(), "", []*unstructured.Unstructured{test.constraint}, req)
			if (err != nil) != test.expectedErr {
				t.Errorf("wanted error state to be %v; got %v", test.expectedErr, err != nil)
			}
			if len(response.Results) > 0 != test.expectedViolations {
				t.Errorf("wanted violation presence to be %v; got %v", test.expectedViolations, spew.Sdump(response.Results))
			}
		})
	}
}
