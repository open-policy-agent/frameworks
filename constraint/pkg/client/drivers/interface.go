package drivers

import (
	"context"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type QueryCfg struct {
	TracingEnabled bool
}

type QueryOpt func(*QueryCfg)

func Tracing(enabled bool) QueryOpt {
	return func(cfg *QueryCfg) {
		cfg.TracingEnabled = enabled
	}
}

type Driver interface {
	// AddTemplate adds the template source code to OPA
	AddTemplate(ct *templates.ConstraintTemplate) error
	// RemoveTemplate removes the template source code from OPA
	RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error

	AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error
	RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error

	AddData(ctx context.Context, key handler.StoragePath, data interface{}) error
	RemoveData(ctx context.Context, key handler.StoragePath) (bool, error)

	Query(ctx context.Context, target string, constraint *unstructured.Unstructured, key handler.StoragePath, review interface{}, opts ...QueryOpt) (rego.ResultSet, *string, error)

	Dump(ctx context.Context) (string, error)
}

type ConstraintKey struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func ConstraintKeyFrom(constraint *unstructured.Unstructured) ConstraintKey {
	return ConstraintKey{
		Kind: constraint.GetKind(),
		Name: constraint.GetName(),
	}
}

func (k ConstraintKey) StoragePath() handler.StoragePath {
	return handler.StoragePath{"constraints", k.Kind, k.Name}
}
