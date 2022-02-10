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
	namespace string
	cache     *Cache
}

// Match returns true if the object under review's Namespace matches the Namespace
// the Matcher filters for. If the object's Namespace is not cached in cache,
// returns an error.
//
// Matches all objects if the Matcher has no namespace specified.
func (m Matcher) Match(review interface{}) (bool, error) {
	if m.namespace == "" {
		return true, nil
	}

	wantNamespace := Object{Namespace: m.namespace}

	key := wantNamespace.Key()
	_, exists := m.cache.Namespaces.Load(key)
	if !exists {
		return false, fmt.Errorf("%w: namespace %q not in cache",
			ErrNotFound, m.namespace)
	}

	reviewObj, ok := review.(*Review)
	if !ok {
		return false, fmt.Errorf("%w: unrecognized type %T, want %T",
			ErrInvalidType, review, &Review{})
	}

	return m.namespace == reviewObj.Object.Namespace, nil
}

var _ constraints.Matcher = Matcher{}
