package client

import (
	"fmt"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	constraintlib "github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// templateClient handles per-ConstraintTemplate operations.
//
// Not threadsafe.
type templateClient struct {
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

func (e *templateClient) ValidateConstraint(constraint *unstructured.Unstructured) error {
	for _, target := range e.targets {
		err := target.ValidateConstraint(constraint)
		if err != nil {
			return err
		}
	}

	return crds.ValidateCR(constraint, e.crd)
}

func (e *templateClient) getTemplate() *templates.ConstraintTemplate {
	return e.template.DeepCopy()
}

func (e *templateClient) Update(templ *templates.ConstraintTemplate, crd *apiextensions.CustomResourceDefinition, targets ...handler.TargetHandler) error {
	cpy := templ.DeepCopy()
	cpy.Status = templates.ConstraintTemplateStatus{}

	matchers := make(map[string]map[string]constraintlib.Matcher)

	for name, constraint := range e.constraints {
		// Ensure that all Constraints pass validation for the Template's new target(s).
		for _, target := range targets {
			err := target.ValidateConstraint(constraint.constraint)
			if err != nil {
				return err
			}
		}

		cMatchers, err := makeMatchers(targets, constraint.constraint)
		if err != nil {
			return err
		}

		matchers[name] = cMatchers
	}

	// Updating e.template must happen after any operations which may fail have
	// completed successfully. This ensures the SemanticEqual exit-early is not
	// triggered unless the Template was previously successfully added.
	e.template = cpy
	e.crd = crd
	e.targets = targets

	for name, constraint := range e.constraints {
		constraint.updateMatchers(matchers[name])
	}

	return nil
}

// AddConstraint adds the Constraint to the Template.
// Returns true and no error if the Constraint was changed successfully.
// Returns false and no error if the Constraint was not updated due to being
// identical to the stored version.
func (e *templateClient) AddConstraint(constraint *unstructured.Unstructured) (bool, error) {
	enforcementAction, err := apiconstraints.GetEnforcementAction(constraint)
	if err != nil {
		return false, err
	}

	// Compare with the already-existing Constraint.
	// If identical, exit early.
	cached, found := e.constraints[constraint.GetName()]
	if found && constraintlib.SemanticEqual(cached.constraint, constraint) {
		return false, nil
	}

	matchers, err := makeMatchers(e.targets, constraint)
	if err != nil {
		return false, err
	}

	err = e.ValidateConstraint(constraint)
	if err != nil {
		return false, err
	}

	e.constraints[constraint.GetName()] = &constraintClient{
		constraint:        constraint.DeepCopy(),
		matchers:          matchers,
		enforcementAction: enforcementAction,
	}

	return true, nil
}

// GetConstraint returns the Constraint with name for this Template.
func (e *templateClient) GetConstraint(name string) (*unstructured.Unstructured, error) {
	constraint, found := e.constraints[name]
	if !found {
		kind := e.template.Spec.CRD.Spec.Names.Kind
		return nil, fmt.Errorf("%w: %q %q", ErrMissingConstraint, kind, name)
	}

	return constraint.getConstraint(), nil
}

func (e *templateClient) RemoveConstraint(name string) {
	delete(e.constraints, name)
}

// Matches returns a map from Constraint names to the results of running Matchers
// against the passed review.
//
// ignoredTargets specifies the targets whose matchers to not run.
func (e *templateClient) Matches(target string, review interface{}) map[string]constraintMatchResult {
	result := make(map[string]constraintMatchResult)

	for name, constraint := range e.constraints {
		cResult := constraint.matches(target, review)
		if cResult != nil {
			result[name] = *cResult
		}
	}

	return result
}
