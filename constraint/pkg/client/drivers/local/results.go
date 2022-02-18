package local

import (
	"encoding/json"

	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/rego"
)

func ToResults(target handler.TargetHandler, resultSet rego.ResultSet) ([]*types.Result, error) {
	var results []*types.Result
	for _, r := range resultSet {
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

		results = append(results, result)
	}

	return results, nil
}
