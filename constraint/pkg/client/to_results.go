package client

import (
	"encoding/json"

	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ToResult(target handler.TargetHandler, constraint *unstructured.Unstructured, review interface{}, r rego.Result) (*types.Result, error) {
	result := &types.Result{}

	b, err := json.Marshal(r.Bindings["result"])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, result)
	if err != nil {
		return nil, err
	}

	err = target.HandleViolation(result)
	if err != nil {
		return nil, err
	}

	result.Constraint = constraint

	enforcementAction, found, _ := unstructured.NestedString(constraint.Object, "spec", "enforcementAction")
	if !found {
		enforcementAction = "deny"
	}

	result.EnforcementAction = enforcementAction
	result.Review = review

	return result, nil
}
