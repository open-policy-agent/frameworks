package handlertest

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ handler.TargetHandler = &Handler{}

var _ handler.Cacher = &Handler{}

// TargetName is the default target name.
const TargetName = "test.target"

// Handler is a test implementation of TargetHandler.
type Handler struct {
	// Name, if set, is the name of the Handler. Otherwise defaults to TargetName.
	Name *string

	// ShouldHandle is whether Handler should handle Object.
	// If unset, handles all Objects.
	ShouldHandle func(*Object) bool

	ForbiddenEnforcement *string

	// ProcessDataError is the error to return when ProcessData is called.
	// If nil returns no error.
	ProcessDataError error

	Cache *Cache
}

// GetName returns the name of the Handler.
func (h *Handler) GetName() string {
	if h.Name != nil {
		return *h.Name
	}

	return TargetName
}

// ProcessData processes the given data object.
func (h *Handler) ProcessData(obj interface{}) (bool, []string, interface{}, error) {
	switch o := obj.(type) {
	case *Object:
		if h.ProcessDataError != nil {
			return false, nil, nil, h.ProcessDataError
		}

		if h.ShouldHandle != nil && !h.ShouldHandle(o) {
			return false, nil, nil, nil
		}

		return true, o.Key(), obj, nil
	default:
		return false, nil, nil, fmt.Errorf("%w: got object type %T, want %T",
			ErrInvalidType, obj, &Object{})
	}
}

// HandleReview handles a review request.
func (h *Handler) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch data := obj.(type) {
	case Review:
		if data.Ignored {
			return false, nil, nil
		}
		return true, &data, nil
	case *Review:
		if data.Ignored {
			return false, nil, nil
		}
		return true, data, nil
	case *Object:
		return true, &Review{Object: *data}, nil
	default:
		return false, nil, fmt.Errorf("unrecognized type %T", obj)
	}
}

// MatchSchema returns the JSON schema for constraint matching.
func (h *Handler) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"matchNamespace": {Type: "string"},
		},
	}
}

// ValidateConstraint validates a constraint.
func (h *Handler) ValidateConstraint(constraint *unstructured.Unstructured) error {
	if h.ForbiddenEnforcement == nil {
		return nil
	}

	enforcementAction, found, err := unstructured.NestedString(constraint.Object, "spec", "enforcementAction")
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	if enforcementAction == *h.ForbiddenEnforcement {
		return fmt.Errorf("forbidden enforcementAction %q", enforcementAction)
	}

	return nil
}

// ToMatcher creates a Matcher from a constraint.
func (h *Handler) ToMatcher(constraint *unstructured.Unstructured) (constraints.Matcher, error) {
	ns, _, err := unstructured.NestedString(constraint.Object, "spec", "match", "matchNamespace")
	if err != nil {
		return nil, fmt.Errorf("unable to get spec.matchNamespace: %w", err)
	}

	return Matcher{Namespace: ns, Cache: h.Cache}, nil
}

// GetCache returns the Cache for the Handler.
func (h *Handler) GetCache() handler.Cache {
	if h.Cache == nil {
		return handler.NoCache{}
	}

	return h.Cache
}
