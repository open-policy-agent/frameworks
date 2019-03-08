package client

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apimachinery/pkg/runtime"
)

// validateTargets ensures that the targets field has the appropriate values
func validateTargets(templ *v1alpha1.ConstraintTemplate) error {
	if len(templ.Spec.Targets) > 1 {
		return errors.New("Multi-target templates are not currently supported")
	} else if len(templ.Spec.Targets) == 0 {
		return errors.New("ConstraintTemplate must specify one target")
	}
	return nil
}

// createSchema combines the schema of the match target and the ConstraintTemplate parameters
// to form the schema of the actual constraint resource
func createSchema(templ *v1alpha1.ConstraintTemplate, target MatchSchemaProvider) *apiextensionsv1beta1.JSONSchemaProps {
	props := map[string]apiextensionsv1beta1.JSONSchemaProps{
		"match": target.MatchSchema(),
	}
	if templ.Spec.CRD.Spec.Validation != nil && templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema != nil {
		props["parameters"] = *templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema
	}
	schema := &apiextensionsv1beta1.JSONSchemaProps{
		Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
			"spec": apiextensionsv1beta1.JSONSchemaProps{
				Properties: props,
			},
		},
	}
	return schema
}

// crdHelper builds the scheme for handling CRDs. It is necessary to build crdHelper at runtime as
// modules are added to the CRD scheme builder during the init stage
type crdHelper struct {
	scheme *runtime.Scheme
}

func newCRDHelper() *crdHelper {
	scheme := runtime.NewScheme()
	apiextensionsv1beta1.AddToScheme(scheme)
	return &crdHelper{scheme: scheme}
}

// createCRD takes a template and a schema and converts it to a CRD
func (h *crdHelper) createCRD(
	templ *v1alpha1.ConstraintTemplate,
	schema *apiextensionsv1beta1.JSONSchemaProps) *apiextensionsv1beta1.CustomResourceDefinition {
	crd := &apiextensionsv1beta1.CustomResourceDefinition{
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group: constraintGroup,
			Names: templ.Spec.CRD.Spec.Names,
			Validation: &apiextensionsv1beta1.CustomResourceValidation{
				OpenAPIV3Schema: schema,
			},
			Scope:   "Cluster",
			Version: v1alpha1.SchemeGroupVersion.Version,
		},
	}
	h.scheme.Default(crd)
	crd.ObjectMeta.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, constraintGroup)
	return crd
}

// validateCRD calls the CRD package's validation on an internal representation of the CRD
func (h *crdHelper) validateCRD(crd *apiextensionsv1beta1.CustomResourceDefinition) error {
	internalCRD := &apiextensions.CustomResourceDefinition{}
	if err := h.scheme.Convert(crd, internalCRD, nil); err != nil {
		return err
	}
	errors := apiextensionsvalidation.ValidateCustomResourceDefinition(internalCRD)
	if len(errors) > 0 {
		return errors.ToAggregate()
	}
	return nil
}
