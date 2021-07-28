package templates

import (
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

var constraintTemplateCRD *apiextensionsv1.CustomResourceDefinition

func init() {
	// Ingest the constraint template CRD for use in defaulting functions
	crdJSON, err := yaml.YAMLToJSONStrict([]byte(constraintTemplateCRDYaml))
	if err != nil {
		panic("Failed to convert Constraint Template yaml to JSON")
	}

	unCRD := unstructured.Unstructured{}
	unCRD.UnmarshalJSON(crdJSON)

	constraintTemplateCRD = &apiextensionsv1.CustomResourceDefinition{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(unCRD.Object, constraintTemplateCRD)
	if err != nil {
		panic("Failed to convert unstructured CRD to apiextensions.CustomResourceDefinition{}")
	}
}

func getVersionSchema(crd *apiextensionsv1.CustomResourceDefinition, version string) (*apiextensionsv1.JSONSchemaProps, error) {
	for _, crdVersion := range crd.Spec.Versions {
		if crdVersion.Name != version {
			continue
		}

		return crdVersion.Schema.OpenAPIV3Schema, nil
	}

	return nil, fmt.Errorf("CRD does not contain version '%v'", version)
}
