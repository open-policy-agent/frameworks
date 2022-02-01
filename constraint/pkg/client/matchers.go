package client

import (
	"fmt"
	"sort"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
)

// matcherKey uniquely identifies a Matcher.
// For a given Constraint (uniquely identified by Kind/Name), there is at most
// one Matcher for each Target.
type matcherKey struct {
	target string
	kind   string
	name   string
}

// constraintMatchers tracks the Matchers for each Constraint.
// Filters Constraints relevant to a passed review.
type constraintMatchers struct {
	// matchers is the set of Constraint matchers by their Target, Kind, and Name.
	// matchers is a map from Target to a map from Kind to a map from Name to matcher.
	matchers map[string]map[string]map[string]constraints.Matcher

	mtx sync.RWMutex
}

// Add inserts the Matcher for the Constraint with kind and name.
// Replaces the current Matcher if one already exists.
func (c *constraintMatchers) Add(key matcherKey, matcher constraints.Matcher) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.matchers == nil {
		c.matchers = make(map[string]map[string]map[string]constraints.Matcher)
	}

	targetMatchers := c.matchers[key.target]
	if targetMatchers == nil {
		targetMatchers = make(map[string]map[string]constraints.Matcher)
	}

	kindMatchers := targetMatchers[key.kind]
	if kindMatchers == nil {
		kindMatchers = make(map[string]constraints.Matcher)
	}

	kindMatchers[key.name] = matcher
	targetMatchers[key.kind] = kindMatchers
	c.matchers[key.target] = targetMatchers
}

// Remove deletes the Matcher for the Constraint with kind and name.
// Returns normally if no entry for the Constraint existed.
func (c *constraintMatchers) Remove(key matcherKey) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.matchers) == 0 {
		return
	}

	targetMatchers := c.matchers[key.target]
	if len(targetMatchers) == 0 {
		return
	}

	kindMatchers := targetMatchers[key.kind]
	if len(kindMatchers) == 0 {
		return
	}

	delete(kindMatchers, key.name)

	// Remove empty parents to avoid memory leaks.
	if len(kindMatchers) == 0 {
		delete(targetMatchers, key.kind)
	} else {
		targetMatchers[key.kind] = kindMatchers
	}

	if len(targetMatchers) == 0 {
		delete(c.matchers, key.target)
	} else {
		c.matchers[key.target] = targetMatchers
	}
}

// RemoveAll removes all Matchers for Constraints with kind.
// Returns normally if no entry for the kind existed.
func (c *constraintMatchers) RemoveAll(kind string) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if len(c.matchers) == 0 {
		return
	}

	for h, handlerMatchers := range c.matchers {
		delete(handlerMatchers, kind)

		if len(handlerMatchers) == 0 {
			// It is safe to delete keys from a map while traversing it.
			delete(c.matchers, h)
		} else {
			c.matchers[h] = handlerMatchers
		}
	}

	delete(c.matchers, kind)
}

// ConstraintsFor returns the set of Constraints which should run against review
// according to their Matchers. Returns a map from Kind to the names of the
// Constraints of that Kind which should be run against review.
//
// Returns errors for each Constraint which was unable to properly run match
// criteria.
func (c *constraintMatchers) ConstraintsFor(review interface{}) (map[string]map[string][]string, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	result := make(map[string]map[string][]string)

	errs := errors.ErrorMap{}

	for target, targetMatchers := range c.matchers {
		resultTargetMatchers := make(map[string][]string)
		for kind, kindMatchers := range targetMatchers {
			var resultKindMatchers []string

			for name, matcher := range kindMatchers {
				if matches, err := matcher.Match(review); err != nil {
					// key uniquely identifies the Constraint whose matcher was unable to
					// run, for use in debugging.
					key := fmt.Sprintf("%s %s %s", target, kind, name)
					errs[key] = err
				} else if matches {
					resultKindMatchers = append(resultKindMatchers, name)
				}
			}

			sort.Strings(resultKindMatchers)
			resultTargetMatchers[kind] = resultKindMatchers
		}

		result[target] = resultTargetMatchers
	}

	if len(errs) > 0 {
		return nil, &errs
	}

	return result, nil
}
