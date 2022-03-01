package client

import (
	"fmt"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// templateClient handles per-ConstraintTemplate operations.
//
// Threadsafe. Use accessor methods for fields to prevent race conditions.
type templateClient struct {
	mtx sync.RWMutex

	// targets are the Targets which
	targets []handler.TargetHandler

	// template is a copy of the original ConstraintTemplate added to Client.
	template *templates.ConstraintTemplate

	// constraints are all currently-known Constraints for this Template.
	constraints map[string]*constraintClient

	// crd is a cache of the generated CustomResourceDefinition generated from
	// this Template. This is used to validate incoming Constraints before adding
	// them.
	crd *apiextensions.CustomResourceDefinition
}

func (e *templateClient) getTargets() []handler.TargetHandler {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	return e.targets
}

func (e *templateClient) setTargets(targets []handler.TargetHandler) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	e.targets = targets
}

func (e *templateClient) setCRD(crd *apiextensions.CustomResourceDefinition) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	e.crd = crd
}

func (e *templateClient) validateConstraint(constraint *unstructured.Unstructured) error {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	return crds.ValidateCR(constraint, e.crd)
}

func (e *templateClient) getTemplate() *templates.ConstraintTemplate {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	return e.template.DeepCopy()
}

func (e *templateClient) setTemplate(template *templates.ConstraintTemplate) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	cpy := template.DeepCopy()
	cpy.Status = templates.ConstraintTemplateStatus{}

	e.template = cpy
}

func (e *templateClient) makeMatchers(targets []handler.TargetHandler) (map[string]map[string]constraints.Matcher, error) {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

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
	e.mtx.Lock()
	defer e.mtx.Unlock()

	for name, constraint := range e.constraints {
		constraint.updateMatchers(matchers[name])
	}
}

func (e *templateClient) addConstraint(constraint *unstructured.Unstructured, matchers map[string]constraints.Matcher, enforcementAction string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	e.constraints[constraint.GetName()] = &constraintClient{
		constraint:        constraint.DeepCopy(),
		matchers:          matchers,
		enforcementAction: enforcementAction,
	}
}

func (e *templateClient) getConstraint(name string) (*unstructured.Unstructured, error) {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

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
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	result := make(map[string]constraintMatchResult)

	for name, constraint := range e.constraints {
		cResult := constraint.matches(target, review)
		if cResult != nil {
			result[name] = *cResult
		}
	}

	return result
}
