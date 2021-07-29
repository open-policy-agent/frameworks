package templates

import (
	"fmt"

	"github.com/pkg/errors"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

var ConstraintTemplateSchemas map[string]*schema.Structural

func init() {
	ConstraintTemplateSchemas = make(map[string]*schema.Structural)

	// Ingest the constraint template CRD for use in defaulting functions
	crdJSON, err := yaml.YAMLToJSONStrict([]byte(constraintTemplateCRDYaml))
	if err != nil {
		panic(errors.Wrap(err, "Failed to convert Constraint Template yaml to JSON"))
	}

	unCRD := unstructured.Unstructured{}
	if err := unCRD.UnmarshalJSON(crdJSON); err != nil {
		panic(errors.Wrap(err, "Failed to unmarshal JSON into unstructured"))
	}
	constraintTemplateCRD := &apiextensionsv1.CustomResourceDefinition{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(unCRD.Object, constraintTemplateCRD)
	if err != nil {
		panic(errors.Wrap(err, "Failed to convert unstructured CRD to apiextensions.CustomResourceDefinition{}"))
	}

	// NewStructural requires apiextensions.JSONSchemaProps, where ConstraintTemplate uses
	// apiextensionsv1.JSONSchemaProps.  Set up scheme for conversion.
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := apiextensions.AddToScheme(scheme); err != nil {
		panic(err)
	}

	// Fill version map with Structural types derived from ConstraintTemplate versions
	for _, crdVersion := range constraintTemplateCRD.Spec.Versions {
		versionlessSchema := &apiextensions.JSONSchemaProps{}
		err := scheme.Convert(crdVersion.Schema.OpenAPIV3Schema, versionlessSchema, nil)
		if err != nil {
			panic(errors.Wrap(err, "Failed to convert JSONSchemaProps"))
		}

		structural, err := schema.NewStructural(versionlessSchema)
		if err != nil {
			panic(errors.Wrap(err, fmt.Sprintf("Failed to create Structural for ConstraintTemplate version %v", crdVersion.Name)))
		}

		ConstraintTemplateSchemas[crdVersion.Name] = structural
	}
}
