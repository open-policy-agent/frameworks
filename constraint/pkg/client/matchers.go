package client

import (
	"fmt"
	"sort"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
)

// constraintMatchers tracks the Matchers for each Constraint.
// Filters Constraints relevant to a passed review.
// Not threadsafe.
//
// Assumes that the possible set of target names is bounded.
// Leaks memory if target names change during runtime.
type constraintMatchers struct {
	// matchers is the set of Constraint matchers by their Target, Kind, and Name.
	// matchers is a map from Target to a map from Kind to a map from Name to matcher.
	matchers map[string]targetMatchers
}

// Upsert updates the Matchers for the Constraint uniquely identified by kind
// and name. For Matchers which already exist for the Constraint, they are:
// 1) Removed if not present in matchers,
// 2) Replaced if present in matchers.
func (c *constraintMatchers) Upsert(key drivers.ConstraintKey, matchers map[string]constraints.Matcher) {
	if c.matchers == nil {
		c.matchers = make(map[string]targetMatchers)
	}

	for targetName, m := range c.matchers {
		_, keep := matchers[targetName]
		if !keep {
			m.Remove(key)
		}
	}

	for targetName, matcher := range matchers {
		tMatchers := c.matchers[targetName]
		tMatchers.Add(key, matcher)
		c.matchers[targetName] = tMatchers
	}
}

// Remove deletes the Matcher for the referenced Constraint and Target.
func (c *constraintMatchers) Remove(target string, key drivers.ConstraintKey) {
	if len(c.matchers) == 0 {
		return
	}

	matchers := c.matchers[target]
	matchers.Remove(key)
}

// RemoveConstraint deletes all Matchers for the Constraint with kind and name.
// Returns normally if no entry for the Constraint existed.
func (c *constraintMatchers) RemoveConstraint(key drivers.ConstraintKey) {
	if len(c.matchers) == 0 {
		return
	}

	for target, matchers := range c.matchers {
		matchers.Remove(key)

		if len(matchers.matchers) == 0 {
			delete(c.matchers, target)
		} else {
			c.matchers[target] = matchers
		}
	}
}

// RemoveKind removes all Matchers for Constraints with kind.
// Returns normally if no entry for the kind exists for any target.
func (c *constraintMatchers) RemoveKind(kind string) {
	if len(c.matchers) == 0 {
		return
	}

	for name, target := range c.matchers {
		target.RemoveKind(kind)

		if len(target.matchers) == 0 {
			// It is safe to delete keys from a map while traversing it.
			delete(c.matchers, name)
		} else {
			c.matchers[name] = target
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
func (c *constraintMatchers) ConstraintsFor(targetName string, review interface{}) ([]drivers.ConstraintKey, error) {
	result := make([]drivers.ConstraintKey, 0)
	target := c.matchers[targetName]
	errs := errors.ErrorMap{}

	for kind, kindMatchers := range target.matchers {
		for name, matcher := range kindMatchers {
			key := drivers.ConstraintKey{
				Kind: kind,
				Name: name,
			}

			if matches, err := matcher.Match(review); err != nil {
				// key uniquely identifies the Constraint whose matcher was unable to
				// run, for use in debugging.
				errKey := fmt.Sprintf("%s %s", targetName, key)
				errs[errKey] = err
			} else if matches {
				result = append(result, key)
			}
		}
	}

	if len(errs) > 0 {
		return nil, &errs
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})

	return result, nil
}

// targetMatchers are the Matchers for Constraints for a specific target.
// Not threadsafe.
type targetMatchers struct {
	matchers map[string]map[string]constraints.Matcher
}

func (t *targetMatchers) Add(key drivers.ConstraintKey, matcher constraints.Matcher) {
	if t.matchers == nil {
		t.matchers = make(map[string]map[string]constraints.Matcher)
	}

	kindMatchers := t.matchers[key.Kind]
	if kindMatchers == nil {
		kindMatchers = make(map[string]constraints.Matcher)
	}

	kindMatchers[key.Name] = matcher
	t.matchers[key.Kind] = kindMatchers
}

func (t *targetMatchers) Remove(key drivers.ConstraintKey) {
	kindMatchers, ok := t.matchers[key.Kind]
	if !ok {
		return
	}

	delete(kindMatchers, key.Name)

	// Remove empty parents to avoid memory leaks.
	if len(kindMatchers) == 0 {
		delete(t.matchers, key.Kind)
	} else {
		t.matchers[key.Kind] = kindMatchers
	}
}

func (t *targetMatchers) RemoveKind(kind string) {
	delete(t.matchers, kind)
}
