package driver

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ToResult(constraint *unstructured.Unstructured, review interface{}, r rego.Result) (*types.Result, error) {
	result := &types.Result{}

	resultMapBinding, found := r.Bindings["result"]
	if !found {
		return nil, errors.New("no binding for result")
	}

	resultMap, ok := resultMapBinding.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("result binding was %T but want %T",
			resultMapBinding, map[string]interface{}{})
	}

	messageBinding, found := resultMap["msg"]
	if !found {
		return nil, errors.New("no binding for msg")
	}

	message, ok := messageBinding.(string)
	if !ok {
		return nil, fmt.Errorf("message binding was %T but want %T",
			messageBinding, "")
	}
	result.Msg = message

	result.Metadata = map[string]interface{}{
		"details": resultMap["details"],
	}

	result.Constraint = constraint

	enforcementAction, found, err := unstructured.NestedString(constraint.Object, "spec", "enforcementAction")
	if err != nil {
		return nil, err
	}
	if !found {
		enforcementAction = "deny"
	}

	result.EnforcementAction = enforcementAction
	result.Review = review

	return result, nil
}
