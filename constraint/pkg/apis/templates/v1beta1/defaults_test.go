package v1beta1

import (
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestSetDefaultsConstraintTemplate(t *testing.T) {
	// The scheme is responsible for defaulting
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	// Create a Constraint Template with legacySchema unset
	ct := &ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConstraintTemplate",
			APIVersion: "templates.gatekeeper.sh/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "MustHaveMoreCats",
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRD{
				Spec: CRDSpec{
					Names: Names{
						Kind:       "MustHaveMoreCats",
						ShortNames: []string{"mhmc"},
					},
					Validation: &Validation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"message": {
									Type: "string",
								},
								"labels": {
									Type: "array",
									Items: &apiextensionsv1.JSONSchemaPropsOrArray{
										Schema: &apiextensionsv1.JSONSchemaProps{
											Type: "object",
											Properties: map[string]apiextensionsv1.JSONSchemaProps{
												"key":          {Type: "string"},
												"allowedRegex": {Type: "string"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Targets: []Target{
				{
					Target: "sometarget",
					Rego:   `package hello ; violation[{"msg": "msg"}] { true }`,
				},
			},
		},
	}

	scheme.Default(ct)

	if ct.Spec.CRD.Spec.Validation.LegacySchema == nil {
		t.Fatalf("legacySchema: Got nil, want true")
	}
	if !(*ct.Spec.CRD.Spec.Validation.LegacySchema) {
		t.Errorf("legacySchema: Got false, want true")
	}
}
