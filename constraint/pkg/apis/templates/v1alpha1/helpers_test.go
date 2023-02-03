package v1alpha1

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	regoSchema "github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/schema"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

func TestToVersionless(t *testing.T) {
	tcs := []struct {
		name      string
		versioned *ConstraintTemplate
		want      *templates.ConstraintTemplate
	}{
		{
			name: "basic conversion",
			versioned: &ConstraintTemplate{
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
			},
			want: &templates.ConstraintTemplate{
				// TypeMeta isn't copied in conversion
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "MustHaveMoreCats",
				},
				Spec: templates.ConstraintTemplateSpec{
					CRD: templates.CRD{
						Spec: templates.CRDSpec{
							Names: templates.Names{
								Kind:       "MustHaveMoreCats",
								ShortNames: []string{"mhmc"},
							},
							Validation: &templates.Validation{
								// A default was applied
								LegacySchema:    pointer.Bool(true),
								OpenAPIV3Schema: schema.VersionlessSchemaWithXPreserve(),
							},
						},
					},
					Targets: []templates.Target{
						{
							Target: "sometarget",
							Rego:   `package hello ; violation[{"msg": "msg"}] { true }`,
							Code: []templates.Code{
								{
									Engine: regoSchema.Name,
									Source: &templates.Anything{
										Value: (&regoSchema.Source{
											Rego: `package hello ; violation[{"msg": "msg"}] { true }`,
										}).ToUnstructured(),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.versioned.ToVersionless()
			if err != nil {
				t.Fatalf("Failed to convert to versionless: %s", err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToVersionless() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
