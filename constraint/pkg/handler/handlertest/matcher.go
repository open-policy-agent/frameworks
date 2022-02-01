package handlertest

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
)

var ErrInvalidType = errors.New("unrecognized type")

type Matcher struct {
	Namespace string
}

func (m Matcher) Match(review interface{}) (bool, error) {
	if m.Namespace == "" {
		return true, nil
	}

	reviewObj, ok := review.(*Review)
	if !ok {
		return false, fmt.Errorf("%w: got %T, want %T",
			ErrInvalidType, review, &Review{})
	}

	return m.Namespace == reviewObj.Object.Namespace, nil
}

var _ constraints.Matcher = Matcher{}
