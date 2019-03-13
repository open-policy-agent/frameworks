package drivers

import (
	"context"

	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
)

type Driver interface {
	Init(ctx context.Context) error
	PutRule(ctx context.Context, name string, src string) error
	DeleteRule(ctx context.Context, name string) (bool, error)

	PutData(ctx context.Context, path string, data interface{}) error
	DeleteData(ctx context.Context, path string) (bool, error)
	Query(ctx context.Context, path string, input interface{}) ([]*types.Result, error)
}
