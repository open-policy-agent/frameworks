package client

import (
	"errors"
	"fmt"
	"strings"
)

var (
	errCreatingBackend           = errors.New("unable to create backend")
	errCreatingClient            = errors.New("unable to create client")
	errInvalidConstraintTemplate = errors.New("invalid ConstraintTemplate")
	errInvalidConstraint         = errors.New("invalid Constraint")
	errInvalidModule             = errors.New("invalid module")
)

type UnrecognizedConstraintError struct {
	s string
}

func (e *UnrecognizedConstraintError) Error() string {
	return fmt.Sprintf("Constraint kind %s is not recognized", e.s)
}

func IsUnrecognizedConstraintError(e error) bool {
	_, ok := e.(*UnrecognizedConstraintError)
	return ok
}

func NewUnrecognizedConstraintError(text string) error {
	return &UnrecognizedConstraintError{text}
}

type MissingConstraintError struct {
	s string
}

func (e *MissingConstraintError) Error() string {
	return fmt.Sprintf("Constraint kind %s is not recognized", e.s)
}

func NewMissingConstraintError(subPath string) error {
	return &MissingConstraintError{subPath}
}

func IsMissingTemplateError(e error) bool {
	_, ok := e.(*MissingTemplateError)
	return ok
}

type MissingTemplateError struct {
	s string
}

func (e *MissingTemplateError) Error() string {
	return fmt.Sprintf("Constraint kind %s is not recognized", e.s)
}

func NewMissingTemplateError(mapKey string) error {
	return &MissingTemplateError{mapKey}
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
