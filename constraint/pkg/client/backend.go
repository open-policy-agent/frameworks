package client

import (
	"errors"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
)

type Backend struct {
	driver drivers.Driver
	crd    *crdHelper
}

type BackendOpt func(*Backend)

func Driver(d drivers.Driver) BackendOpt {
	return func(b *Backend) {
		b.driver = d
	}
}

// NewBackend creates a new backend. A backend could be a connection to a remote server or
// a new local OPA instance.
func NewBackend(opts ...BackendOpt) (*Backend, error) {
	b := &Backend{crd: newCRDHelper()}
	for _, opt := range opts {
		opt(b)
	}

	if b.driver == nil {
		return nil, errors.New("No driver supplied to the backend")
	}

	return b, nil
}

// NewClient creates a new client for the supplied backend
func (b *Backend) NewClient(opts ...ClientOpt) (*client, error) {
	return &client{backend: b}, nil
}
