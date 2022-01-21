package clienttest

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

	for _, arg := range args {
		err := arg(u)
		if err != nil {
			t.Fatal(err)
		}
	}

	return u
}

type ConstraintArg func(*unstructured.Unstructured) error

// EnableAutoreject enables autorejecting requests to review Objects the constraint
// matches.
func EnableAutoreject(u *unstructured.Unstructured) error {
	return unstructured.SetNestedField(u.Object, true, "spec", "autoreject")
}

// MatchNamespace modifies the Constraint to only match objects with the passed
// Namespace.
func MatchNamespace(namespace string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, namespace, "spec", "matchNamespace")
	}
}

// WantData sets the Constraint to verify that data of objects under review is
// set to wantData. Only meaningful for CheckData constraints.
func WantData(data string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, data, "spec", "parameters", "wantData")
	}
}

// EnforcementAction sets the action to be taken if the Constraint is violated.
func EnforcementAction(action string) ConstraintArg {
	return func(u *unstructured.Unstructured) error {
		return unstructured.SetNestedField(u.Object, action, "spec", "enforcementAction")
	}
}
