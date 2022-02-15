package handlertest

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrInvalidType = errors.New("invalid type")
)

// Matcher is a test matcher which matches Objects with a matching namespace.
// Checks that Namespace exists in cache before proceeding.
type Matcher struct {
	Namespace string
	Cache     *Cache
}

// Match returns true if the object under review's Namespace matches the Namespace
// the Matcher filters for. If the object's Namespace is not cached in cache,
// returns an error.
//
// Matches all objects if the Matcher has no namespace specified.
func (m Matcher) Match(review interface{}) (bool, error) {
	if m.Namespace == "" {
		return true, nil
	}

	if m.Cache == nil {
		return false, fmt.Errorf("missing cache")
	}

	reviewObj, ok := review.(*Review)
	if !ok {
		return false, fmt.Errorf("%w: got %T, want %T",
			ErrInvalidType, review, &Review{})
	}

	key := Object{Namespace: reviewObj.Object.Namespace}.Key()
	_, exists := m.Cache.Namespaces.Load(key)
	if !exists {
		return false, fmt.Errorf("%w: namespace %q not in cache",
			ErrNotFound, m.Namespace)
	}

	return m.Namespace == reviewObj.Object.Namespace, nil
}

var _ constraints.Matcher = Matcher{}
