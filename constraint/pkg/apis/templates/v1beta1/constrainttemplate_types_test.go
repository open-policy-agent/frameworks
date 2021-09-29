/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	apisTemplates "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"golang.org/x/net/context"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestStorageConstraintTemplate(t *testing.T) {
	key := types.NamespacedName{
		Name: "foo",
	}
	created := &ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
	}
	g := gomega.NewGomegaWithT(t)

	// Test Create
	fetched := &ConstraintTemplate{}
	g.Expect(c.Create(context.TODO(), created)).NotTo(gomega.HaveOccurred())

	g.Expect(c.Get(context.TODO(), key, fetched)).NotTo(gomega.HaveOccurred())
	g.Expect(fetched).To(gomega.Equal(created))

	// Test Updating the Labels
	updated := fetched.DeepCopy()
	updated.Labels = map[string]string{"hello": "world"}
	g.Expect(c.Update(context.TODO(), updated)).NotTo(gomega.HaveOccurred())

	g.Expect(c.Get(context.TODO(), key, fetched)).NotTo(gomega.HaveOccurred())
	g.Expect(fetched).To(gomega.Equal(updated))

	// Test Delete
	g.Expect(c.Delete(context.TODO(), fetched)).NotTo(gomega.HaveOccurred())
	g.Expect(c.Get(context.TODO(), key, fetched)).To(gomega.HaveOccurred())
}

func TestTypeConversion(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("Could not add to scheme: %v", err)
	}
	versioned := &ConstraintTemplate{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConstraintTemplate",
			APIVersion: "templates.gatekeeper.sh/v1beta1",
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
	}
	versionedCopy := versioned.DeepCopy()
	// Kind and API Version do not survive the conversion process
	versionedCopy.Kind = ""
	versionedCopy.APIVersion = ""

	unversioned := &templates.ConstraintTemplate{}
	if err := scheme.Convert(versioned, unversioned, nil); err != nil {
		t.Fatalf("Conversion error: %v", err)
	}
	recast := &ConstraintTemplate{}
	if err := scheme.Convert(unversioned, recast, nil); err != nil {
		t.Fatalf("Recast conversion error: %v", err)
	}
}

// TestValidationVersionConversionAndTransformation confirms that our custom conversion
// function works, and also that it adds in the x-kubernetes-preserve-unknown-fields information
// that we require for v1 CRD support.
func TestValidationVersionConversionAndTransformation(t *testing.T) {
	// The scheme is responsible for defaulting
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	trueBool := true
	falseBool := false
	testCases := []struct {
		name string
		v    *Validation
		exp  *templates.Validation
	}{
		{
			name: "Two deep properties, LegacySchema=true",
			v: &Validation{
				LegacySchema:    &trueBool,
				OpenAPIV3Schema: apisTemplates.VersionedIncompleteSchema(),
			},
			exp: &templates.Validation{
				LegacySchema:    &trueBool,
				OpenAPIV3Schema: apisTemplates.VersionlessSchemaWithXPreserve(),
			},
		},
		{
			name: "Two deep properties, LegacySchema=false",
			v: &Validation{
				LegacySchema:    &falseBool,
				OpenAPIV3Schema: apisTemplates.VersionedIncompleteSchema(),
			},
			exp: &templates.Validation{
				LegacySchema:    &falseBool,
				OpenAPIV3Schema: apisTemplates.VersionlessSchema(),
			},
		},
		{
			name: "Two deep properties, LegacySchema=nil",
			v: &Validation{
				OpenAPIV3Schema: apisTemplates.VersionedIncompleteSchema(),
			},
			exp: &templates.Validation{
				OpenAPIV3Schema: apisTemplates.VersionlessSchema(),
			},
		},
		{
			name: "Nil properties, LegacySchema=true",
			v: &Validation{
				LegacySchema:    &trueBool,
				OpenAPIV3Schema: nil,
			},
			exp: &templates.Validation{
				LegacySchema: &trueBool,
				OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
					XPreserveUnknownFields: &trueBool,
				},
			},
		},
		{
			name: "Nil properties, LegacySchema=false",
			v: &Validation{
				LegacySchema:    &falseBool,
				OpenAPIV3Schema: nil,
			},
			exp: &templates.Validation{
				LegacySchema:    &falseBool,
				OpenAPIV3Schema: nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := &templates.Validation{}
			if err := scheme.Convert(tc.v, out, nil); err != nil {
				t.Fatalf("Conversion error: %v", err)
			}

			if !reflect.DeepEqual(out, tc.exp) {
				t.Fatalf("Conversion does not match expected result: %v", cmp.Diff(out, tc.exp))
			}
		})
	}
}
