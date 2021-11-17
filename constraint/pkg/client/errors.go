package client

import (
	"errors"
	"strings"
)

var (
	ErrCreatingBackend           = errors.New("unable to create backend")
	ErrCreatingClient            = errors.New("unable to create client")
	ErrInvalidConstraintTemplate = errors.New("invalid ConstraintTemplate")
	ErrInvalidConstraint         = errors.New("invalid Constraint")
	ErrMissingConstraintTemplate = errors.New("missing ConstraintTemplate")
	ErrMissingConstraint         = errors.New("missing Constraint")
	ErrInvalidModule             = errors.New("invalid module")
)

// IsUnrecognizedConstraintError returns true if err is an ErrMissingConstraint.
//
// Deprecated: Use errors.Is(err, ErrMissingConstraint) instead.
func IsUnrecognizedConstraintError(err error) bool {
	return errors.Is(err, ErrMissingConstraint)
}

// Errors is a list of error.
//
// Deprecated: Use a structured result type if it is important to disambiguate
// errors (for tests or error handling). Otherwise,.
type Errors []error

// Errors implements error.
var _ error = Errors{}

// Error implements error.
func (errs Errors) Error() string {
	return ToError(errs)
}

// ToError combines multiple errors into a single error message. The original
// errors cannot be extracted (for tests or programmatic error handling).
func ToError(errs []error) string {
	s := make([]string, len(errs))
	for _, e := range errs {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}
