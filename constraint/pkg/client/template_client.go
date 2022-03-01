package client

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// templateClient handles per-ConstraintTemplate operations.
type templateClient struct {
	// template is a copy of the original ConstraintTemplate added to Client.
	template *templates.ConstraintTemplate

	// constraints are all currently-known Constraints for this Template.
	constraints map[string]*constraintClient

	// crd is a cache of the generated CustomResourceDefinition generated from
	// this Template. This is used to validate incoming Constraints before adding
	// them.
	crd *apiextensions.CustomResourceDefinition
}

func (e *templateClient) Targets() []string {
	result := make([]string, 0, len(e.template.Spec.Targets))
	for _, t := range e.template.Spec.Targets {
		result = append(result, t.Target)
	}
	return result
}

func (e *templateClient) validateConstraint(constraint *unstructured.Unstructured) error {
	return crds.ValidateCR(constraint, e.crd)
}

func (e *templateClient) getTemplate() *templates.ConstraintTemplate {
	return e.template.DeepCopy()
}

func (e *templateClient) makeMatchers(targets []handler.TargetHandler) (map[string]map[string]constraints.Matcher, error) {
	result := make(map[string]map[string]constraints.Matcher)

	for name, constraint := range e.constraints {
		matchers, err := makeMatchers(targets, constraint.constraint)

		if err != nil {
			return nil, err
		}

		result[name] = matchers
	}

	return result, nil
}

func (e *templateClient) updateMatchers(matchers map[string]map[string]constraints.Matcher) {
	for name, cMatchers := range matchers {
		e.constraints[name].updateMatchers(cMatchers)
	}
}

func (e *templateClient) addConstraint(constraint *unstructured.Unstructured, matchers map[string]constraints.Matcher, enforcementAction string) {
	e.constraints[constraint.GetName()] = &constraintClient{
		constraint:        constraint.DeepCopy(),
		matchers:          matchers,
		enforcementAction: enforcementAction,
	}
}

func (e *templateClient) getConstraint(name string) (*unstructured.Unstructured, error) {
	constraint, found := e.constraints[name]
	if !found {
		kind := e.template.Spec.CRD.Spec.Names.Kind
		return nil, fmt.Errorf("%w: %q %q", ErrMissingConstraint, kind, name)
	}

	return constraint.getConstraint(), nil
}

func (e *templateClient) removeConstraint(name string) {
	delete(e.constraints, name)
}

// matches returns a map from Constraint names to the results of running Matchers
// against the passed review.
//
// ignoredTargets specifies the targets whose matchers to not run.
func (e *templateClient) matches(target string, review interface{}) map[string]constraintMatchResult {
	result := make(map[string]constraintMatchResult)

	for name, constraint := range e.constraints {
		cResult := constraint.matches(target, review)
		if cResult != nil {
			result[name] = *cResult
		}
	}

	return result
}
