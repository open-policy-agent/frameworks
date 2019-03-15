package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/regolib"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const constraintGroup = "constraints.gatekeeper.sh"

type Client interface {
	AddData(context.Context, interface{}) error
	RemoveData(context.Context, interface{}) error

	AddTemplate(context.Context, *v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, error)
	RemoveTemplate(context.Context, *v1alpha1.ConstraintTemplate) error

	AddConstraint(context.Context, *unstructured.Unstructured) error
	RemoveConstraint(context.Context, *unstructured.Unstructured) error
	ValidateConstraint(context.Context, *unstructured.Unstructured) error

	// Reset the state of OPA
	Reset(context.Context) error

	// Review makes sure the provided object satisfies all stored constraints
	Review(context.Context, interface{}) ([]*types.Result, error)

	// Audit makes sure the cached state of the system satisfies all stored constraints
	Audit(context.Context) ([]*types.Result, error)
}

type ClientOpt func(*client) error

// Client options

func Targets(ts ...TargetHandler) ClientOpt {
	return func(c *client) error {
		var errs Errors
		handlers := make(map[string]TargetHandler, len(ts))
		for _, t := range ts {
			if t.GetName() == "" {
				errs = append(errs, errors.New("Invalid target: a target is returning an empty string for GetName()"))
			} else {
				handlers[t.GetName()] = t
			}
		}
		c.targets = handlers
		if len(errs) > 0 {
			return errs
		}
		return nil
	}
}

type MatchSchemaProvider interface {
	// MatchSchema returns the JSON Schema for the `match` field of a constraint
	MatchSchema() apiextensionsv1beta1.JSONSchemaProps
}

type TargetHandler interface {
	MatchSchemaProvider

	GetName() string

	// Library returns the pieces of Rego code required to stitch together constraint evaluation
	// for the target. Current required libraries are `matching_constraints` and
	// `matching_reviews_and_constraints`
	Library() string

	// ProcessData takes a potential data object and returns:
	//   true if the target handles the data type
	//   the path under which the data should be stored in OPA
	//   the data in an object that can be cast into JSON, suitable for storage in OPA
	ProcessData(interface{}) (bool, string, interface{}, error)
}

var _ Client = &client{}

type constraintEntry struct {
	CRD     *apiextensionsv1beta1.CustomResourceDefinition
	Targets []string
}

type client struct {
	backend        *Backend
	targets        map[string]TargetHandler
	constraintsMux sync.RWMutex
	constraints    map[string]*constraintEntry
}

// createDataPath compiles the data destination: data.external.<target>.<path>
func createDataPath(target, subpath string) string {
	subpaths := strings.Split(subpath, "/")
	p := []string{"", "external", target}
	p = append(p, subpaths...)

	return path.Join(p...)
}

// AddData inserts the provided data into OPA for every target that can handle the data.
func (c *client) AddData(ctx context.Context, data interface{}) error {
	for target, h := range c.targets {
		handled, path, processedData, err := h.ProcessData(data)
		// Should we instead swallow errors and log them to avoid poorly-behaved targets
		// short-circuiting calls?
		if err != nil {
			return err
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
		handled, path, _, err := h.ProcessData(data)
		// Should we instead swallow errors and log them to avoid poorly-behaved targets
		// short-circuiting calls?
		if err != nil {
			return err
		}
		if !handled {
			continue
		}
		// Same short-circuiting question here
		if _, err := c.backend.driver.DeleteData(ctx, createDataPath(target, path)); err != nil {
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
func (c *client) AddTemplate(ctx context.Context, templ *v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, error) {
	if err := validateTargets(templ); err != nil {
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

	schema := createSchema(templ, target)
	crd := c.backend.crd.createCRD(templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		return nil, err
	}

	path := createTemplatePath(target.GetName(), crd.Spec.Names.Kind)
	conformingSrc, err := ensureRegoConformance(crd.Spec.Names.Kind, path, src)
	if err != nil {
		return nil, err
	}

	c.constraintsMux.Lock()
	defer c.constraintsMux.Unlock()
	if err := c.backend.driver.PutRule(ctx, path, conformingSrc); err != nil {
		return nil, err
	}

	c.constraints[crd.Spec.Names.Kind] = &constraintEntry{CRD: crd, Targets: []string{target.GetName()}}
	crdCopy := &apiextensionsv1beta1.CustomResourceDefinition{}
	crd.DeepCopyInto(crdCopy)

	return crdCopy, nil
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry.
func (c *client) RemoveTemplate(ctx context.Context, templ *v1alpha1.ConstraintTemplate) error {
	if err := validateTargets(templ); err != nil {
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

	schema := createSchema(templ, target)
	crd := c.backend.crd.createCRD(templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		return err
	}

	path := createTemplatePath(target.GetName(), templ.Spec.CRD.Spec.Names.Kind)

	c.constraintsMux.Lock()
	defer c.constraintsMux.Unlock()
	_, err := c.backend.driver.DeleteRule(ctx, path)
	if err != nil {
		return err
	}
	delete(c.constraints, crd.Spec.Names.Kind)
	return nil
}

// createConstraintPath returns the storage path for a given constraint: constraints.<target>.cluster.<group>.<version>.<kind>.<name>
func createConstraintPath(target string, constraint *unstructured.Unstructured) (string, error) {
	if constraint.GetName() == "" {
		return "", errors.New("Constraint has no name")
	}
	gvk := constraint.GroupVersionKind()
	if gvk.Group == "" {
		return "", fmt.Errorf("Empty group for the constrant named %s", constraint.GetName())
	}
	if gvk.Version == "" {
		return "", fmt.Errorf("Empty version for the constraint named %s", constraint.GetName())
	}
	if gvk.Kind == "" {
		return "", fmt.Errorf("Empty kind for the constraint named %s", constraint.GetName())
	}
	return path.Join("constraints", target, "cluster", gvk.Group, gvk.Version, gvk.Kind, constraint.GetName()), nil
}

// getConstraintEntry returns the constraint entry for a given constraint
func (c *client) getConstraintEntry(constraint *unstructured.Unstructured, lock bool) (*constraintEntry, error) {
	kind := constraint.GetKind()
	if kind == "" {
		return nil, fmt.Errorf("Constraint %s has no kind", constraint.GetName())
	}
	if lock {
		c.constraintsMux.RLock()
		defer c.constraintsMux.RUnlock()
	}
	entry, ok := c.constraints[kind]
	if !ok {
		return nil, fmt.Errorf("Constraint kind %s is not recognized", kind)
	}
	return entry, nil
}

// AddConstraint validates the constraint and, if valid, inserts it into OPA
func (c *client) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	c.constraintsMux.RLock()
	defer c.constraintsMux.RUnlock()
	if err := c.validateConstraint(constraint, false); err != nil {
		return err
	}
	entry, err := c.getConstraintEntry(constraint, false)
	if err != nil {
		return err
	}
	for _, target := range entry.Targets {
		path, err := createConstraintPath(target, constraint)
		// If we ever create multi-target constraints we will need to handle this more cleverly.
		// the short-circuiting question, cleanup, etc.
		if err != nil {
			return err
		}
		if err := c.backend.driver.PutData(ctx, path, constraint); err != nil {
			return err
		}
	}
	return nil
}

// RemoveConstraint removes a constraint from OPA
func (c *client) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	c.constraintsMux.RLock()
	defer c.constraintsMux.RUnlock()
	entry, err := c.getConstraintEntry(constraint, false)
	if err != nil {
		return err
	}
	for _, target := range entry.Targets {
		path, err := createConstraintPath(target, constraint)
		// If we ever create multi-target constraints we will need to handle this more cleverly.
		// the short-circuiting question, cleanup, etc.
		if err != nil {
			return err
		}
		if _, err := c.backend.driver.DeleteData(ctx, path); err != nil {
			return err
		} else {
		}

	}
	return nil
}

// validateConstraint is an internal function that allows us to toggle whether we use a read lock
// when validating a constraint
func (c *client) validateConstraint(constraint *unstructured.Unstructured, lock bool) error {
	entry, err := c.getConstraintEntry(constraint, lock)
	if err != nil {
		return err
	}
	return c.backend.crd.validateCR(constraint, entry.CRD)
}

// ValidateConstraint returns an error if the constraint is not recognized or does not conform to
// the registered CRD for that constraint.
func (c *client) ValidateConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	return c.validateConstraint(constraint, true)
}

// init initializes the OPA backend for the client
func (c *client) init() error {
	for _, t := range c.targets {
		hooks := fmt.Sprintf("hooks.%s", t.GetName())
		templMap := map[string]string{"Target": t.GetName()}

		deny := &bytes.Buffer{}
		if err := regolib.Deny.Execute(deny, templMap); err != nil {
			return err
		}
		if err := c.backend.driver.PutRule(
			context.Background(),
			fmt.Sprintf("%s.deny", hooks),
			deny.String()); err != nil {
			return err
		}

		audit := &bytes.Buffer{}
		if err := regolib.Audit.Execute(audit, templMap); err != nil {
			return err
		}
		if err := c.backend.driver.PutRule(
			context.Background(),
			fmt.Sprintf("%s.audit", hooks),
			audit.String()); err != nil {
			return err
		}

		lib := t.Library()
		req := ruleArities{
			"matching_reviews_and_constraints": 2,
			"matching_constraints":             1,
		}
		if err := requireRules(fmt.Sprintf("%s_libraries", t.GetName()), lib, req); err != nil {
			return err
		}
		if err := c.backend.driver.PutRule(
			context.Background(),
			fmt.Sprintf("%s.library", hooks),
			lib); err != nil {
			return err
		}
	}

	return nil
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
