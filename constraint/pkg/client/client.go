package client

import (
	"context"
	"errors"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Client interface {
	AddData(context.Context, interface{}) error
	RemoveData(context.Context, interface{}) error

	AddTemplate(context.Context, v1alpha1.ConstraintTemplate) error
	RemoveTemplate(context.Context, v1alpha1.ConstraintTemplate) error

	AddConstraint(context.Context, unstructured.Unstructured) error
	RemoveConstraint(context.Context, unstructured.Unstructured) error

	// Reset the state of OPA
	Reset(context.Context) error

	// Review makes sure the provided object satisfies all stored constraints
	Review(context.Context, interface{}) ([]*types.Result, error)

	// Audit makes sure the cached state of the system satisfies all stored constraints
	Audit(context.Context) ([]*types.Result, error)
}

type TargetHandler interface {
	GetName() string

	// Libraries are the pieces of Rego code required to stitch together constraint evaluation
	// for the target. Current required libraries are `matching_constraints` and
	// `matching_reviews_and_constraints`
	Libraries() map[string][]byte

	// MatchSchema returns the JSON Schema for the `match` field of a constraint
	MatchSchema() apiextensionsv1beta1.JSONSchemaProps

	// ProcessData takes a potential data object and returns:
	//   true if the target handles the data type
	//   the path under which the data should be stored in OPA
	//   the data in an object that can be cast into JSON, suitable for storage in OPA
	ProcessData(interface{}) (bool, string, interface{}, error)
}

var _ Client = &client{}

type client struct {
	Backend *Backend
}

func (c *client) AddData(ctx context.Context, data interface{}) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) RemoveData(ctx context.Context, data interface{}) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) AddTemplate(ctx context.Context, templ v1alpha1.ConstraintTemplate) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) RemoveTemplate(ctx context.Context, templ v1alpha1.ConstraintTemplate) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) AddConstraint(ctx context.Context, constraint unstructured.Unstructured) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) RemoveConstraint(ctx context.Context, constraint unstructured.Unstructured) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) Reset(ctx context.Context) error {
	return errors.New("NOT IMPLEMENTED")
}

func (c *client) Review(ctx context.Context, obj interface{}) ([]*types.Result, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

func (c *client) Audit(ctx context.Context) ([]*types.Result, error) {
	return nil, errors.New("NOT IMPLEMENTED")
}

type Backend struct {
	driver drivers.Driver
}

type BackendOpt func(*Backend)

func Driver(d drivers.Driver) BackendOpt {
	return func(b *Backend) {
		b.driver = d
	}
}

func NewBackend(opts ...BackendOpt) (*Backend, error) {
	b := &Backend{}
	for _, opt := range opts {
		opt(b)
	}

	if b.driver == nil {
		return nil, errors.New("No driver supplied to the backend")
	}

	return b, nil
}

type ClientOpt func(*client)

func (b *Backend) NewClient(opts ...ClientOpt) (*client, error) {
	return &client{Backend: b}, nil
}
