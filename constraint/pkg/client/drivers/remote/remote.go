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

func (d *driver) Init(ctx context.Context) error {
	return nil
}

func (d *driver) PutRule(ctx context.Context, name string, src string) error {
	return d.opa.InsertPolicy(name, []byte(src))
}

// DeleteRule deletes a rule from OPA and returns true if a rule was found and deleted, false
// if a rule was not found, and any errors
func (d *driver) DeleteRule(ctx context.Context, name string) (bool, error) {
	err := d.opa.DeletePolicy(name)
	if err != nil {
		if e, ok := err.(*Error); ok {
			if e.Code == types.CodeResourceNotFound {
				return false, nil
			}
		}
	}
	return err == nil, err
}

func (d *driver) PutData(ctx context.Context, path string, data interface{}) error {
	return d.opa.PutData(path, data)
}

// DeleteData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors
func (d *driver) DeleteData(ctx context.Context, path string) (bool, error) {
	err := d.opa.DeleteData(path)
	if err != nil {
		if e, ok := err.(*Error); ok {
			if e.Code == types.CodeResourceNotFound {
				return false, nil
			}
		}
	}
	return err == nil, err
}

func (d *driver) Query(ctx context.Context, path string, input interface{}) ([]*ctypes.Result, error) {
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
