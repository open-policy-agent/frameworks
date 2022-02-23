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
	RemoveTemplate(ct *templates.ConstraintTemplate) error

	PutData(ctx context.Context, key handler.Key, data interface{}) error
	DeleteData(ctx context.Context, key handler.Key) (bool, error)

	Query(ctx context.Context, target string, constraint *unstructured.Unstructured, key handler.Key, review interface{}, opts ...QueryOpt) (rego.ResultSet, *string, error)

	Dump(ctx context.Context) (string, error)
}
