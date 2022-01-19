package handlertest

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
)

type Matcher struct {
	namespace string
}

func (m Matcher) Match(review interface{}) (bool, error) {
	if m.namespace == "" {
		return true, nil
	}

	reviewObj, ok := review.(*Review)
	if !ok {
		return false, fmt.Errorf("unrecognized type %T, want %T",
			review, &Review{})
	}

	return m.namespace == reviewObj.Object.Namespace, nil
}

var _ constraints.Matcher = Matcher{}
