package crds

import "errors"

var (
	ErrInvalidConstraintTemplate = errors.New("invalid ConstraintTemplate")
	ErrInvalidConstraint         = errors.New("invalid Constraint")
)
