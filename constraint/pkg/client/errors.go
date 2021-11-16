package client

import (
	"errors"
	"fmt"
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
