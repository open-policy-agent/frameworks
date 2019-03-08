package remote

import (
	"context"
	"crypto/x509"
	"encoding/json"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	ctypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/server/types"
)

func New(url string, opaCAs *x509.CertPool, auth string) drivers.Driver {
	return &driver{opa: newHttpClient(url, opaCAs, auth)}
}

var _ drivers.Driver = &driver{}

type driver struct {
	opa client
}

func (d driver) Init(ctx context.Context) error {
	return nil
}

func (d driver) PutRule(ctx context.Context, name string, src string) error {
	return d.opa.InsertPolicy(name, []byte(src))
}

func (d driver) DeleteRule(ctx context.Context, name string) error {
	return d.opa.DeletePolicy(name)
}

func (d driver) PutData(ctx context.Context, path string, data interface{}) error {
	return d.opa.PutData(path, data)
}

func (d driver) DeleteData(ctx context.Context, path string) error {
	err := d.opa.DeleteData(path)
	if err != nil {
		if e, ok := err.(*Error); ok {
			if e.Code == types.CodeResourceNotFound {
				return nil
			}
		}
	}
	return err
}

func (d driver) Query(ctx context.Context, path string, input interface{}) ([]*ctypes.Result, error) {
	response, err := d.opa.Query(path, input)
	if err != nil {
		return nil, err
	}
	var results []*ctypes.Result

	if err := json.Unmarshal(response, &results); err != nil {
		return nil, err
	}

	return results, nil
}
