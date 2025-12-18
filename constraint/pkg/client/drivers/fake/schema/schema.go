// Package schema defines the source schema for the fake driver.
package schema

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	// ErrBadType is returned when the source type cannot be recognized.
	ErrBadType = errors.New("could not recognize the type")
	// ErrMissingField is returned when a required field is missing from the source.
	ErrMissingField = errors.New("rego source missing required field")
)

// Source represents the source configuration for a fake driver.
type Source struct {
	// RejectWith is the rejection message
	RejectWith string `json:"rejectWith,omitempty"`
}

// ToUnstructured converts the Source to an unstructured map representation.
func (in *Source) ToUnstructured() map[string]interface{} {
	if in == nil {
		return nil
	}

	out := map[string]interface{}{}
	out["rejectWith"] = in.RejectWith

	return out
}

// GetSource extracts Source from a templates.Code object.
func GetSource(code templates.Code) (*Source, error) {
	rawCode := code.Source
	v, ok := rawCode.Value.(map[string]interface{})
	if !ok {
		return nil, ErrBadType
	}
	source := &Source{}
	rejectWith, found, err := unstructured.NestedString(v, "rejectWith")
	if err != nil {
		return nil, fmt.Errorf("%w: while extracting source", err)
	}
	if !found {
		return nil, fmt.Errorf("%w: rejectWith", ErrMissingField)
	}
	source.RejectWith = rejectWith

	return source, nil
}
