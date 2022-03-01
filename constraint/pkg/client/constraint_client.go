package client

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// constraintClient handler per-Constraint operations.
type constraintClient struct {
	// constraint is a copy of the original Constraint added to Client.
	constraint *unstructured.Unstructured

	// enforcementAction is what should be done if the Constraint is violated or
	// fails to run on a review.
	enforcementAction string

	// matchers are the per-target Matchers for this Constraint.
	matchers map[string]constraints.Matcher
}

func (c *constraintClient) getConstraint() *unstructured.Unstructured {
	return c.constraint.DeepCopy()
}

func (c *constraintClient) makeMatchers(targets []handler.TargetHandler) (map[string]constraints.Matcher, error) {
	result := make(map[string]constraints.Matcher)

	for _, target := range targets {
		matcher, err := target.ToMatcher(c.constraint)
		if err != nil {
			return nil, fmt.Errorf("making matcher for %q: %v",
				target.GetName(), err)
		}

		result[target.GetName()] = matcher
	}

	return result, nil
}

func (c *constraintClient) updateMatchers(matchers map[string]constraints.Matcher) {
	c.matchers = matchers
}

func (c *constraintClient) matches(target string, review interface{}) *constraintMatchResult {
	matcher, found := c.matchers[target]
	if !found {
		return nil
	}

	matches, err := matcher.Match(review)

	switch {
	case err != nil:
		// Run the Constraint's enforcementAction since we were unable to determine
		// if the Constraint matched.
		return &constraintMatchResult{
			constraint:        c.constraint,
			error:             fmt.Errorf("%w: %v", errors.ErrAutoreject, err),
			enforcementAction: c.enforcementAction,
		}
	case matches:
		// Fill in Constraint, so we can pass it to the Driver to run.
		return &constraintMatchResult{
			constraint: c.constraint,
		}
	default:
		// No match and no error, so no need to record a result.
		return nil
	}
}

type constraintMatchResult struct {
	// constraint is a pointer to the Constraint. Not safe for modification.
	constraint *unstructured.Unstructured
	// enforcementAction, if specified, is the immediate action to take.
	// Only filled in if error is non-nil.
	enforcementAction string
	// error is a problem encountered while attempting to run the Constraint's
	// Matcher.
	error error
}

func (r *constraintMatchResult) ToResult() *types.Result {
	return &types.Result{
		Msg:               r.error.Error(),
		Constraint:        r.constraint,
		EnforcementAction: r.enforcementAction,
	}
}
