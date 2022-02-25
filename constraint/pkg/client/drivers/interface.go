package drivers

import (
	"context"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A Driver implements Rego query execution of Templates and Constraints.
type Driver interface {
	AddTemplate(ct *templates.ConstraintTemplate) error
	RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error

	AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error
	RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error

	AddData(ctx context.Context, path storage.Path, data interface{}) error
	RemoveData(ctx context.Context, path storage.Path) error

	Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...QueryOpt) ([]*types.Result, *string, error)

	Dump(ctx context.Context) (string, error)
}

// ConstraintKey uniquely identifies a Constraint.
type ConstraintKey struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ConstraintKeyFrom returns a unique identifier corresponding to Constraint.
func ConstraintKeyFrom(constraint *unstructured.Unstructured) ConstraintKey {
	return ConstraintKey{
		Kind: constraint.GetKind(),
		Name: constraint.GetName(),
	}
}

// StoragePath returns a unique path in Rego storage for Constraint's parameters.
// Constraints have a single set of parameters shared among all targets, so a
// target-specific path is not required.
func (k ConstraintKey) StoragePath() storage.Path {
	return storage.Path{"constraints", k.Kind, k.Name}
}
