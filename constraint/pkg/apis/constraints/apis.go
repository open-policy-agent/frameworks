package constraints

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const Group = "constraints.gatekeeper.sh"

const (
	// EnforcementActionDeny indicates that if a review fails validation for a
	// Constraint, that it should be rejected. Errors encountered running
	// validation are treated as failing validation.
	//
	// This is the default EnforcementAction.
	EnforcementActionDeny = "deny"
	// EnforcementActionWarn indicates that a warning should be logged or printed
	// if a review fails validation, or if the Constraint fails to run.
	EnforcementActionWarn = "warn"
)

var ErrInvalidConstraint = errors.New("invalid Constraint")

// GetEnforcementAction returns a Constraint's enforcementAction, which indicates
// what should be done if a review violates a Constraint, or the Constraint fails
// to run.
//
// Returns an error if spec.enforcementAction is defined and is not a string.
func GetEnforcementAction(constraint *unstructured.Unstructured) (string, error) {
	action, found, err := unstructured.NestedString(constraint.Object, "spec", "enforcementAction")
	if err != nil {
		return "", fmt.Errorf("%w: invalid spec.enforcementAction", ErrInvalidConstraint)
	}

	if !found {
		return EnforcementActionDeny, nil
	}

	return action, nil
}
