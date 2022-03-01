package client

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type templateEntry struct {
	// template is a copy of the original ConstraintTemplate added to Client.
	template *templates.ConstraintTemplate
	// constraints are all currently-known Constraints for this Template.
	constraints map[string]*unstructured.Unstructured
	// crd is a cache of the generated CustomResourceDefinition generated from
	// this Template. This is used to validate incoming Constraints before adding
	// them.
	crd *apiextensions.CustomResourceDefinition
}

func (e *templateEntry) Targets() []string {
	result := make([]string, 0, len(e.template.Spec.Targets))
	for _, t := range e.template.Spec.Targets {
		result = append(result, t.Target)
	}
	return result
}

func (e *templateEntry) validateConstraint(constraint *unstructured.Unstructured) error {
	return crds.ValidateCR(constraint, e.crd)
}

func (e *templateEntry) getTemplate() *templates.ConstraintTemplate {
	return e.template.DeepCopy()
}

func (e *templateEntry) addConstraint(constraint *unstructured.Unstructured) {
	e.constraints[constraint.GetName()] = constraint.DeepCopy()
}

func (e *templateEntry) getConstraint(name string) (*unstructured.Unstructured, error) {
	constraint, found := e.constraints[name]
	if !found {
		kind := e.template.Spec.CRD.Spec.Names.Kind
		return nil, fmt.Errorf("%w: %q %q", ErrMissingConstraint, kind, name)
	}

	return constraint.DeepCopy(), nil
}

func (e *templateEntry) deleteConstraint(name string) {
	delete(e.constraints, name)
}
