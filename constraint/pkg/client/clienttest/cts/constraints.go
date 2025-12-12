package cts

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// MakeConstraint creates a new test Constraint.
func MakeConstraint(t testing.TB, kind, name string, args ...ConstraintArg) *unstructured.Unstructured {
	t.Helper()

	u := &unstructured.Unstructured{Object: make(map[string]interface{})}

	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constraints.Group,
		Version: "v1beta1",
		Kind:    kind,
	})
	u.SetName(name)

	err := unstructured.SetNestedField(u.Object, make(map[string]interface{}), "spec", "parameters")
	if err != nil {
		t.Fatal(err)
	}

	err = unstructured.SetNestedField(u.Object, "deny", "spec", "enforcementAction")
	if err != nil {
		t.Fatal(err)
	}

	for _, arg := range args {
		err = arg(u)
		if err != nil {
			t.Fatal(err)
		}
	}

	return u
}

func MakeConstraintWithoutActions(t testing.TB, kind, name string, args ...ConstraintArg) *unstructured.Unstructured {
	t.Helper()

	u := &unstructured.Unstructured{Object: make(map[string]interface{})}

	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constraints.Group,
		Version: "v1beta1",
		Kind:    kind,
	})
	u.SetName(name)
	err := unstructured.SetNestedField(u.Object, make(map[string]interface{}), "spec", "parameters")
	if err != nil {
		t.Fatal(err)
	}

	for _, arg := range args {
		err = arg(u)
		if err != nil {
			t.Fatal(err)
		}
	}

	return u
}

func MakeScopedEnforcementConstraint(t testing.TB, kind, name string, globalAction string, actions []string, eps ...string) *unstructured.Unstructured {
	t.Helper()

	scopedEnforcementActions := make([]interface{}, len(actions))

	for i, action := range actions {
		enfocementPoints := make([]interface{}, len(eps))
		for j, point := range eps {
			enfocementPoints[j] = map[string]interface{}{"name": point}
		}
		scopedEnforcementActions[i] = map[string]interface{}{
			"enforcementPoints": enfocementPoints,
			"action":            action,
		}
	}

	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"scopedEnforcementActions": scopedEnforcementActions,
		},
	}}

	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constraints.Group,
		Version: "v1beta1",
		Kind:    kind,
	})
	u.SetName(name)

	err := unstructured.SetNestedField(u.Object, make(map[string]interface{}), "spec", "parameters")
	if err != nil {
		t.Fatal(err)
	}

	err = unstructured.SetNestedField(u.Object, globalAction, "spec", "enforcementAction")
	if err != nil {
		t.Fatal(err)
	}

	return u
}

type ConstraintArg func(*unstructured.Unstructured) error

// MatchNamespace modifies the Constraint to only match objects with the passed
// Namespace.
func MatchNamespace(namespace string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, namespace, "spec", "match", "matchNamespace")
	}
}

// WantData sets the Constraint to verify that data of objects under review is
// set to wantData. Only meaningful for CheckData constraints.
func WantData(data string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, data, "spec", "parameters", "wantData")
	}
}

// WantEnvironment sets the expected namespace environment label.
// Only meaningful for CheckNamespace constraints.
func WantEnvironment(env string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, env, "spec", "parameters", "wantEnvironment")
	}
}

// EnforcementAction sets the action to be taken if the Constraint is violated.
func EnforcementAction(action string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, action, "spec", "enforcementAction")
	}
}

// Set sets an arbitrary value inside the Constraint.
func Set(value interface{}, path ...string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, value, path...)
	}
}
