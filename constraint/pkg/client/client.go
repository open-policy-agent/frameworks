package client

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const constraintGroup = "constraints.gatekeeper.sh"

type Client interface {
	AddData(context.Context, interface{}) error
	RemoveData(context.Context, interface{}) error

	AddTemplate(context.Context, v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, error)
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

type ClientOpt func(*client)

type MatchSchemaProvider interface {
	// MatchSchema returns the JSON Schema for the `match` field of a constraint
	MatchSchema() apiextensionsv1beta1.JSONSchemaProps
}

type TargetHandler interface {
	MatchSchemaProvider

	GetName() string

	// Libraries returns the pieces of Rego code required to stitch together constraint evaluation
	// for the target. Current required libraries are `matching_constraints` and
	// `matching_reviews_and_constraints`
	Libraries() map[string][]byte

	// ProcessData takes a potential data object and returns:
	//   true if the target handles the data type
	//   the path under which the data should be stored in OPA
	//   the data in an object that can be cast into JSON, suitable for storage in OPA
	ProcessData(interface{}) (bool, string, interface{}, error)
}

var _ Client = &client{}

type client struct {
	backend           *Backend
	targets           map[string]TargetHandler
	constraintCRDsMux sync.RWMutex
	constraintCRDs    map[string]*apiextensionsv1beta1.CustomResourceDefinition
}

// createDataPath compiles the data destination: data.external.<target>.<path>
func createDataPath(target, subpath string) string {
	subpaths := strings.Split(subpath, "/")
	p := []string{"", "data", "external", target}
	p = append(p, subpaths...)

	return path.Join(p...)
}

// AddData inserts the provided data into OPA for every target that can handle the data.
func (c *client) AddData(ctx context.Context, data interface{}) error {
	for target, h := range c.targets {
		handled, path, processedData, error := h.ProcessData(data)
		// Should we instead swallow errors and log them to avoid poorly-behaved targets
		// short-circuiting calls?
		if error != nil {
			return error
		}
		if !handled {
			continue
		}
		// Same short-circuiting question here
		if err := c.backend.driver.PutData(ctx, createDataPath(target, path), processedData); err != nil {
			return err
		}
	}
	return nil
}

// RemoveData removes data from OPA for every target that can handle the data.
func (c *client) RemoveData(ctx context.Context, data interface{}) error {
	for target, h := range c.targets {
		handled, path, _, error := h.ProcessData(data)
		// Should we instead swallow errors and log them to avoid poorly-behaved targets
		// short-circuiting calls?
		if error != nil {
			return error
		}
		if !handled {
			continue
		}
		// Same short-circuiting question here
		if err := c.backend.driver.DeleteData(ctx, createDataPath(target, path)); err != nil {
			return err
		}
	}
	return nil
}

// createTemplatePath returns the package path for a given template: templates.<target>.<name>
func createTemplatePath(target, name string) string {
	return fmt.Sprintf("templates.%s.%s", target, name)
}

// AddTemplate adds the template source code to OPA and registers the CRD with the client for
// schema validation on calls to AddConstraint. It also returns a copy of the CRD describing
// the constraint.
func (c *client) AddTemplate(ctx context.Context, templ v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, error) {
	if err := validateTargets(&templ); err != nil {
		return nil, err
	}

	var src string
	var target TargetHandler
	for k, v := range templ.Spec.Targets {
		t, ok := c.targets[k]
		if !ok {
			return nil, fmt.Errorf("Target %s not recognized", k)
		}
		target = t
		src = v.Rego
	}

	schema := createSchema(&templ, target)
	crd := c.backend.crd.createCRD(&templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		return nil, err
	}

	path := createTemplatePath(target.GetName(), crd.Spec.Names.Kind)
	conformingSrc, err := ensureRegoConformance(crd.Spec.Names.Kind, path, src)
	if err != nil {
		return nil, err
	}

	c.constraintCRDsMux.Lock()
	defer c.constraintCRDsMux.Unlock()
	if err := c.backend.driver.PutRule(ctx, path, conformingSrc); err != nil {
		return nil, err
	}

	c.constraintCRDs[crd.Spec.Names.Kind] = crd
	crdCopy := &apiextensionsv1beta1.CustomResourceDefinition{}
	crd.DeepCopyInto(crdCopy)

	return crdCopy, nil
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry.
func (c *client) RemoveTemplate(ctx context.Context, templ v1alpha1.ConstraintTemplate) error {
	if err := validateTargets(&templ); err != nil {
		return err
	}

	var target TargetHandler
	for k := range templ.Spec.Targets {
		t, ok := c.targets[k]
		if !ok {
			return fmt.Errorf("Target %s not recognized", k)
		}
		target = t
	}

	schema := createSchema(&templ, target)
	crd := c.backend.crd.createCRD(&templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		return err
	}

	path := createTemplatePath(target.GetName(), templ.Spec.CRD.Spec.Names.Kind)

	c.constraintCRDsMux.Lock()
	defer c.constraintCRDsMux.Unlock()
	if err := c.backend.driver.DeleteRule(ctx, path); err != nil {
		return err
	}

	delete(c.constraintCRDs, crd.Spec.Names.Kind)
	return nil
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
