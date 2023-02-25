package schema

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	ErrBadType      = errors.New("Could not recognize the type")
	ErrMissingField = errors.New("Rego source missing required field")
)

type Source struct {
	// RejectWith is the rejection message
	RejectWith string `json:"rejectWith,omitempty"`
}

func (in *Source) ToUnstructured() map[string]interface{} {
	if in == nil {
		return nil
	}

	out := map[string]interface{}{}
	out["rejectWith"] = in.RejectWith

	return out
}

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
