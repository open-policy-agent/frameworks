package client

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1beta1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	apivalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"
)

var supportedVersions = map[string]bool{
	v1alpha1.SchemeGroupVersion.Version: true,
	v1beta1.SchemeGroupVersion.Version:  true,
}

// validateTargets ensures that the targets field has the appropriate values.
func validateTargets(templ *templates.ConstraintTemplate) error {
	targets := templ.Spec.Targets
	if targets == nil {
		return fmt.Errorf(`%w: field "targets" not specified in ConstraintTemplate spec`,
			ErrInvalidConstraintTemplate)
	}

	switch len(targets) {
	case 0:
		return fmt.Errorf("%w: no targets specified: ConstraintTemplate must specify one target",
			ErrInvalidConstraintTemplate)
	case 1:
		return nil
	default:
		return fmt.Errorf("%w: multi-target templates are not currently supported",
			ErrInvalidConstraintTemplate)
	}
}

// createSchema combines the schema of the match target and the ConstraintTemplate parameters
// to form the schema of the actual constraint resource
func (h *crdHelper) createSchema(templ *templates.ConstraintTemplate, target MatchSchemaProvider) *apiextensions.JSONSchemaProps {
	props := map[string]apiextensions.JSONSchemaProps{
		"match":             target.MatchSchema(),
		"enforcementAction": {Type: "string"},
	}

	if templ.Spec.CRD.Spec.Validation != nil && templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema != nil {
		internalSchema := *templ.Spec.CRD.Spec.Validation.OpenAPIV3Schema.DeepCopy()
		props["parameters"] = internalSchema
	}

	schema := &apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"metadata": {
				Type: "object",
				Properties: map[string]apiextensions.JSONSchemaProps{
					"name": {
						Type:      "string",
						MaxLength: func(i int64) *int64 { return &i }(63),
					},
				},
			},
			"spec": {
				Type:       "object",
				Properties: props,
			},
			"status": {
				XPreserveUnknownFields: pointer.BoolPtr(true),
			},
		},
	}
	return schema
}

// crdHelper builds the scheme for handling CRDs. It is necessary to build crdHelper at runtime as
// modules are added to the CRD scheme builder during the init stage.
type crdHelper struct {
	scheme *runtime.Scheme
}

func newCRDHelper() (*crdHelper, error) {
	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return &crdHelper{scheme: scheme}, nil
}

// createCRD takes a template and a schema and converts it to a CRD.
func (h *crdHelper) createCRD(
	templ *templates.ConstraintTemplate,
	schema *apiextensions.JSONSchemaProps) (*apiextensions.CustomResourceDefinition, error) {
	crd := &apiextensions.CustomResourceDefinition{
		Spec: apiextensions.CustomResourceDefinitionSpec{
			PreserveUnknownFields: pointer.Bool(false),
			Group:                 constraintGroup,
			Names: apiextensions.CustomResourceDefinitionNames{
				Kind:       templ.Spec.CRD.Spec.Names.Kind,
				ListKind:   templ.Spec.CRD.Spec.Names.Kind + "List",
				Plural:     strings.ToLower(templ.Spec.CRD.Spec.Names.Kind),
				Singular:   strings.ToLower(templ.Spec.CRD.Spec.Names.Kind),
				ShortNames: templ.Spec.CRD.Spec.Names.ShortNames,
				Categories: []string{
					"constraint",
					"constraints",
				},
			},
			Validation: &apiextensions.CustomResourceValidation{
				OpenAPIV3Schema: schema,
			},
			Scope:   apiextensions.ClusterScoped,
			Version: v1beta1.SchemeGroupVersion.Version,
			Subresources: &apiextensions.CustomResourceSubresources{
				Status: &apiextensions.CustomResourceSubresourceStatus{},
				Scale:  nil,
			},
			Versions: []apiextensions.CustomResourceDefinitionVersion{
				{
					Name:    v1beta1.SchemeGroupVersion.Version,
					Storage: true,
					Served:  true,
				},
				{
					Name:    v1alpha1.SchemeGroupVersion.Version,
					Storage: false,
					Served:  true,
				},
			},
			AdditionalPrinterColumns: []apiextensions.CustomResourceColumnDefinition{
				{
					Name:        "enforcement-action",
					Description: "Type of enforcement action",
					JSONPath:    ".spec.enforcementAction",
					Type:        "string",
				},
				{
					Name:        "total-violations",
					Description: "Total number of violations",
					JSONPath:    ".status.totalViolations",
					Type:        "integer",
				},
			},
		},
	}

	// Defaulting functions are not found in versionless CRD package
	crdv1 := &apiextensionsv1.CustomResourceDefinition{}
	if err := h.scheme.Convert(crd, crdv1, nil); err != nil {
		return nil, err
	}
	h.scheme.Default(crdv1)

	crd2 := &apiextensions.CustomResourceDefinition{}
	if err := h.scheme.Convert(crdv1, crd2, nil); err != nil {
		return nil, err
	}
	crd2.ObjectMeta.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, constraintGroup)

	labels := templ.ObjectMeta.Labels
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["gatekeeper.sh/constraint"] = "yes"
	crd2.ObjectMeta.Labels = labels

	return crd2, nil
}

// validateCRD calls the CRD package's validation on an internal representation of the CRD.
func (h *crdHelper) validateCRD(crd *apiextensions.CustomResourceDefinition) error {
	errs := apiextensionsvalidation.ValidateCustomResourceDefinition(crd, apiextensionsv1.SchemeGroupVersion)
	if len(errs) > 0 {
		return errs.ToAggregate()
	}
	return nil
}

// validateCR validates the provided custom resource against its CustomResourceDefinition.
func (h *crdHelper) validateCR(cr *unstructured.Unstructured, crd *apiextensions.CustomResourceDefinition) error {
	validator, _, err := validation.NewSchemaValidator(crd.Spec.Validation)
	if err != nil {
		return err
	}
	if err := validation.ValidateCustomResource(field.NewPath(""), cr, validator); err != nil {
		return err.ToAggregate()
	}

	if errs := apivalidation.IsDNS1123Subdomain(cr.GetName()); len(errs) != 0 {
		return fmt.Errorf("%w: invalid name: %q",
			ErrInvalidConstraint, strings.Join(errs, "\n"))
	}

	if cr.GetKind() != crd.Spec.Names.Kind {
		return fmt.Errorf("%w: wrong kind %q for constraint %q; want %q",
			ErrInvalidConstraint, cr.GetName(), cr.GetKind(), crd.Spec.Names.Kind)
	}

	if cr.GroupVersionKind().Group != constraintGroup {
		return fmt.Errorf("%w: unsupported group %q for constraint %q; allowed group: %q",
			ErrInvalidConstraint, cr.GetName(), cr.GroupVersionKind().Group, constraintGroup)
	}

	if !supportedVersions[cr.GroupVersionKind().Version] {
		return fmt.Errorf("%w: unsupported version %q for Constraint %q; supported versions: %v",
			ErrInvalidConstraint, cr.GroupVersionKind().Version, cr.GetName(), supportedVersions)
	}
	return nil
}
