package transform

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/k8scel/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestTemplateToPolicyDefinition(t *testing.T) {
	tests := []struct {
		name        string
		kind        string
		source      *schema.Source
		expectedErr error
		expected    *admissionregistrationv1alpha1.ValidatingAdmissionPolicy
	}{
		{
			name: "Valid Template",
			kind: "SomePolicy",
			source: &schema.Source{
				FailurePolicy: ptr.To[string]("Fail"),
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "must_match_something",
						Expression: "true == true",
					},
				},
				Variables: []schema.Variable{
					{
						Name:       "my_variable",
						Expression: "true",
					},
				},
				Validations: []schema.Validation{
					{
						Expression:        "1 == 1",
						Message:           "some fallback message",
						MessageExpression: `"some CEL string"`,
					},
				},
			},
			expected: &admissionregistrationv1alpha1.ValidatingAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "g8r-somepolicy",
				},
				Spec: admissionregistrationv1alpha1.ValidatingAdmissionPolicySpec{
					ParamKind: &admissionregistrationv1alpha1.ParamKind{
						APIVersion: "v1beta1",
						Kind:       "SomePolicy",
					},
					MatchConditions: []admissionregistrationv1alpha1.MatchCondition{
						{
							Name:       "must_match_something",
							Expression: "true == true",
						},
						{
							Name:       "g8r_match_excluded_namespaces",
							Expression: matchExcludedNamespacesGlob,
						},
						{
							Name:       "g8r_match_namespaces",
							Expression: matchNamespacesGlob,
						},
						{
							Name:       "g8r_match_name",
							Expression: matchNameGlob,
						},
						{
							Name:       "g8r_match_kinds",
							Expression: matchKinds,
						},
					},
					Validations: []admissionregistrationv1alpha1.Validation{
						{
							Expression:        "1 == 1",
							Message:           "some fallback message",
							MessageExpression: `"some CEL string"`,
						},
					},
					FailurePolicy: ptr.To[admissionregistrationv1alpha1.FailurePolicyType](admissionregistrationv1alpha1.Fail),
					Variables: []admissionregistrationv1alpha1.Variable{
						{
							Name:       "my_variable",
							Expression: "true",
						},
						{
							Name:       schema.ParamsName,
							Expression: "params.spec.parameters",
						},
					},
				},
			},
		},
		{
			name: "Invalid Match Condition",
			kind: "SomePolicy",
			source: &schema.Source{
				FailurePolicy: ptr.To[string]("Fail"),
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "g8r_match_something",
						Expression: "true == true",
					},
				},
				Variables: []schema.Variable{
					{
						Name:       "my_variable",
						Expression: "true",
					},
				},
				Validations: []schema.Validation{
					{
						Expression:        "1 == 1",
						Message:           "some fallback message",
						MessageExpression: `"some CEL string"`,
					},
				},
			},
			expectedErr: schema.ErrBadMatchCondition,
		},
		{
			name: "Invalid Variable",
			kind: "SomePolicy",
			source: &schema.Source{
				FailurePolicy: ptr.To[string]("Fail"),
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "match_something",
						Expression: "true == true",
					},
				},
				Variables: []schema.Variable{
					{
						Name:       "g8r_my_variable",
						Expression: "true",
					},
				},
				Validations: []schema.Validation{
					{
						Expression:        "1 == 1",
						Message:           "some fallback message",
						MessageExpression: `"some CEL string"`,
					},
				},
			},
			expectedErr: schema.ErrBadVariable,
		},
		{
			name: "No Clobbering Params",
			kind: "SomePolicy",
			source: &schema.Source{
				FailurePolicy: ptr.To[string]("Fail"),
				MatchConditions: []schema.MatchCondition{
					{
						Name:       "match_something",
						Expression: "true == true",
					},
				},
				Variables: []schema.Variable{
					{
						Name:       "params",
						Expression: "true",
					},
				},
				Validations: []schema.Validation{
					{
						Expression:        "1 == 1",
						Message:           "some fallback message",
						MessageExpression: `"some CEL string"`,
					},
				},
			},
			expectedErr: schema.ErrBadVariable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawSrc := test.source.MustToUnstructured()

			template := &templates.ConstraintTemplate{
				ObjectMeta: metav1.ObjectMeta{
					Name: strings.ToLower(test.kind),
				},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind: test.kind,
							},
						},
					},
					Targets: []templates.Target{
						{
							Code: []templates.Code{
								{
									Engine: schema.Name,
									Source: &templates.Anything{
										Value: rawSrc,
									},
								},
							},
						},
					},
				},
			}

			obj, err := TemplateToPolicyDefinition(template)
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("unexpected error. got %v; wanted %v", err, test.expectedErr)
			}
			if !reflect.DeepEqual(obj, test.expected) {
				t.Errorf("got %+v\n\nwant %+v", *obj, *test.expected)
			}
		})
	}
}
