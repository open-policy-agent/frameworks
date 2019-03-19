package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1alpha1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/regolib"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const constraintGroup = "constraints.gatekeeper.sh"

type Client interface {
	AddData(context.Context, interface{}) *TargetResponse
	RemoveData(context.Context, interface{}) *TargetResponse

	AddTemplate(context.Context, *v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, *TargetResponse)
	RemoveTemplate(context.Context, *v1alpha1.ConstraintTemplate) *TargetResponse

	AddConstraint(context.Context, *unstructured.Unstructured) *TargetResponse
	RemoveConstraint(context.Context, *unstructured.Unstructured) *TargetResponse
	ValidateConstraint(context.Context, *unstructured.Unstructured) error

	// Reset the state of OPA
	Reset(context.Context) error

	// Review makes sure the provided object satisfies all stored constraints
	Review(context.Context, interface{}) (types.Responses, *TargetResponse)

	// Audit makes sure the cached state of the system satisfies all stored constraints
	Audit(context.Context) (types.Responses, *TargetResponse)

	// Dump dumps the state of OPA to aid in debugging
	Dump(context.Context) (string, error)
}

func NewTargetResponse() *TargetResponse {
	return &TargetResponse{
		Errors:  make(ErrorMap),
		Handled: make(map[string]bool),
	}
}

type ErrorMap map[string]error

func (e ErrorMap) Error() string {
	b := &strings.Builder{}
	for k, v := range e {
		fmt.Fprintf(b, "%s: %s\n", k, v)
	}
	return b.String()
}

type TargetResponse struct {
	Handled map[string]bool
	// Per-target errors
	Errors ErrorMap
	// Fundamental error in the request
	BasicError error
}

func (r *TargetResponse) HandledCount() int {
	c := 0
	for _, h := range r.Handled {
		if h {
			c += 1
		}
	}
	return c
}

func (r *TargetResponse) HasErrors() bool {
	return r.BasicError != nil || len(r.Errors) != 0
}

func (r *TargetResponse) Error() error {
	if r.BasicError != nil {
		return r.BasicError
	}
	if len(r.Errors) != 0 {
		return r.Errors
	}
	return nil
}

type ClientOpt func(*client) error

// Client options

var targetNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`)

func Targets(ts ...TargetHandler) ClientOpt {
	return func(c *client) error {
		var errs Errors
		handlers := make(map[string]TargetHandler, len(ts))
		for _, t := range ts {
			if t.GetName() == "" {
				errs = append(errs, errors.New("Invalid target: a target is returning an empty string for GetName()"))
			} else if !targetNameRegex.MatchString(t.GetName()) {
				errs = append(errs, fmt.Errorf("Target name \"%s\" is not of the form %s", t.GetName(), targetNameRegex.String()))
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
	//
	// Libraries are currently templates that have the following parameters:
	//   ConstraintsRoot: The root path under which all constraints for the target are stored
	//   DataRoot: The root path under which all data for the target is stored
	Library() *template.Template

	// ProcessData takes a potential data object and returns:
	//   true if the target handles the data type
	//   the path under which the data should be stored in OPA
	//   the data in an object that can be cast into JSON, suitable for storage in OPA
	ProcessData(interface{}) (bool, string, interface{}, error)

	// HandleReview takes a potential review request and builds the `review` field of the input
	// object. it returns:
	//		true if the target handles the data type
	//		the data for the `review` field
	HandleReview(interface{}) (bool, interface{}, error)

	// HandleViolation allows for post-processing of the result object, which can be mutated directly
	HandleViolation(result *types.Result) error
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
	p := []string{"external", target}
	p = append(p, subpaths...)

	return "/" + path.Join(p...)
}

// AddData inserts the provided data into OPA for every target that can handle the data.
func (c *client) AddData(ctx context.Context, data interface{}) *TargetResponse {
	resp := NewTargetResponse()
	for target, h := range c.targets {
		handled, path, processedData, err := h.ProcessData(data)
		if err != nil {
			resp.Errors[target] = err
			continue
		}
		if !handled {
			continue
		}
		if err := c.backend.driver.PutData(ctx, createDataPath(target, path), processedData); err != nil {
			resp.Errors[target] = err
			continue
		}
		resp.Handled[target] = true
	}
	return resp
}

// RemoveData removes data from OPA for every target that can handle the data.
func (c *client) RemoveData(ctx context.Context, data interface{}) *TargetResponse {
	resp := NewTargetResponse()
	for target, h := range c.targets {
		handled, path, _, err := h.ProcessData(data)
		if err != nil {
			resp.Errors[target] = err
			continue
		}
		if !handled {
			continue
		}
		if _, err := c.backend.driver.DeleteData(ctx, createDataPath(target, path)); err != nil {
			resp.Errors[target] = err
			continue
		}
		resp.Handled[target] = true
	}
	return resp
}

// createTemplatePath returns the package path for a given template: templates.<target>.<name>
func createTemplatePath(target, name string) string {
	return fmt.Sprintf("templates.%s.%s", target, name)
}

// AddTemplate adds the template source code to OPA and registers the CRD with the client for
// schema validation on calls to AddConstraint. It also returns a copy of the CRD describing
// the constraint.
func (c *client) AddTemplate(ctx context.Context, templ *v1alpha1.ConstraintTemplate) (*apiextensionsv1beta1.CustomResourceDefinition, *TargetResponse) {
	resp := NewTargetResponse()
	if err := validateTargets(templ); err != nil {
		resp.BasicError = err
		return nil, resp
	}
	if templ.ObjectMeta.Name == "" {
		resp.BasicError = errors.New("Template has no name")
		return nil, resp
	}

	var src string
	var target TargetHandler
	for k, v := range templ.Spec.Targets {
		t, ok := c.targets[k]
		if !ok {
			// Currently this is a basic error because only single-target templates are supported
			resp.BasicError = fmt.Errorf("Target %s not recognized", k)
			return nil, resp
		}
		target = t
		src = v.Rego
	}

	schema := createSchema(templ, target)
	crd := c.backend.crd.createCRD(templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		resp.BasicError = err
		return nil, resp
	}

	path := createTemplatePath(target.GetName(), crd.Spec.Names.Kind)
	conformingSrc, err := ensureRegoConformance(crd.Spec.Names.Kind, path, src)
	if err != nil {
		resp.BasicError = err
		return nil, resp
	}

	c.constraintsMux.Lock()
	defer c.constraintsMux.Unlock()
	if err := c.backend.driver.PutModule(ctx, path, conformingSrc); err != nil {
		resp.BasicError = err
		return nil, resp
	}

	c.constraints[crd.Spec.Names.Kind] = &constraintEntry{CRD: crd, Targets: []string{target.GetName()}}
	crdCopy := &apiextensionsv1beta1.CustomResourceDefinition{}
	crd.DeepCopyInto(crdCopy)
	resp.Handled[target.GetName()] = true

	return crdCopy, resp
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry.
func (c *client) RemoveTemplate(ctx context.Context, templ *v1alpha1.ConstraintTemplate) *TargetResponse {
	resp := NewTargetResponse()
	if err := validateTargets(templ); err != nil {
		resp.BasicError = err
		return resp
	}

	var target TargetHandler
	for k := range templ.Spec.Targets {
		t, ok := c.targets[k]
		if !ok {
			resp.BasicError = fmt.Errorf("Target %s not recognized", k)
			return resp
		}
		target = t
	}

	schema := createSchema(templ, target)
	crd := c.backend.crd.createCRD(templ, schema)
	if err := c.backend.crd.validateCRD(crd); err != nil {
		resp.BasicError = err
		return resp
	}

	path := createTemplatePath(target.GetName(), templ.Spec.CRD.Spec.Names.Kind)

	c.constraintsMux.Lock()
	defer c.constraintsMux.Unlock()
	_, err := c.backend.driver.DeleteModule(ctx, path)
	if err != nil {
		resp.BasicError = err
		return resp
	}
	delete(c.constraints, crd.Spec.Names.Kind)
	resp.Handled[target.GetName()] = true
	return resp
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
	return "/" + path.Join("constraints", target, "cluster", gvk.Group, gvk.Version, gvk.Kind, constraint.GetName()), nil
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
func (c *client) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) *TargetResponse {
	c.constraintsMux.RLock()
	defer c.constraintsMux.RUnlock()
	resp := NewTargetResponse()
	if err := c.validateConstraint(constraint, false); err != nil {
		resp.BasicError = err
		return resp
	}
	entry, err := c.getConstraintEntry(constraint, false)
	if err != nil {
		resp.BasicError = err
		return resp
	}
	for _, target := range entry.Targets {
		path, err := createConstraintPath(target, constraint)
		// If we ever create multi-target constraints we will need to handle this more cleverly.
		// the short-circuiting question, cleanup, etc.
		if err != nil {
			resp.Errors[target] = err
			continue
		}
		if err := c.backend.driver.PutData(ctx, path, constraint.Object); err != nil {
			resp.Errors[target] = err
			continue
		}
		resp.Handled[target] = true
	}
	return resp
}

// RemoveConstraint removes a constraint from OPA
func (c *client) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) *TargetResponse {
	c.constraintsMux.RLock()
	defer c.constraintsMux.RUnlock()
	resp := NewTargetResponse()
	entry, err := c.getConstraintEntry(constraint, false)
	if err != nil {
		resp.BasicError = err
		return resp
	}
	for _, target := range entry.Targets {
		path, err := createConstraintPath(target, constraint)
		// If we ever create multi-target constraints we will need to handle this more cleverly.
		// the short-circuiting question, cleanup, etc.
		if err != nil {
			resp.Errors[target] = err
			continue
		}
		if _, err := c.backend.driver.DeleteData(ctx, path); err != nil {
			resp.Errors[target] = err
		}
		resp.Handled[target] = true
	}
	return resp
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
		if err := c.backend.driver.PutModule(
			context.Background(),
			fmt.Sprintf("%s.deny", hooks),
			deny.String()); err != nil {
			return err
		}

		audit := &bytes.Buffer{}
		if err := regolib.Audit.Execute(audit, templMap); err != nil {
			return err
		}
		if err := c.backend.driver.PutModule(
			context.Background(),
			fmt.Sprintf("%s.audit", hooks),
			audit.String()); err != nil {
			return err
		}

		libTempl := t.Library()
		if libTempl == nil {
			return fmt.Errorf("Target %s has no Rego library template", t.GetName())
		}
		libBuf := &bytes.Buffer{}
		if err := libTempl.Execute(libBuf, map[string]string{
			"ConstraintsRoot": fmt.Sprintf(`data.constraints.%s.cluster["%s"].v1alpha1`, t.GetName(), constraintGroup),
			"DataRoot":        fmt.Sprintf(`data.external.%s`, t.GetName()),
		}); err != nil {
			return err
		}
		lib := libBuf.String()
		req := ruleArities{
			"matching_reviews_and_constraints": 2,
			"matching_constraints":             1,
		}
		if err := requireRules(fmt.Sprintf("%s_libraries", t.GetName()), lib, req); err != nil {
			return fmt.Errorf("Problem with the below rego for %s target:\n\n====%s\n====\n%s", t.GetName(), lib, err)
		}
		path := fmt.Sprintf("%s.library", hooks)
		src, err := rewritePackage(path, lib)
		if err != nil {
			return err
		}
		if err := c.backend.driver.PutModule(context.Background(), path, src); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) Reset(ctx context.Context) error {
	c.constraintsMux.Lock()
	defer c.constraintsMux.Unlock()
	for name := range c.targets {
		if _, err := c.backend.driver.DeleteData(ctx, fmt.Sprintf("/external/%s", name)); err != nil {
			return err
		}
		if _, err := c.backend.driver.DeleteData(ctx, fmt.Sprintf("/constraints/%s", name)); err != nil {
			return err
		}
	}
	for name, v := range c.constraints {
		for _, t := range v.Targets {
			if _, err := c.backend.driver.DeleteModule(ctx, fmt.Sprintf("templates.%s.%s", t, name)); err != nil {
				return err
			}
		}
	}
	c.constraints = make(map[string]*constraintEntry)
	return nil
}

func (c *client) Review(ctx context.Context, obj interface{}) (types.Responses, *TargetResponse) {
	tResp := NewTargetResponse()
	responses := types.Responses{}
TargetLoop:
	for name, target := range c.targets {
		handled, review, err := target.HandleReview(obj)
		// Short-circuiting question applies here as well
		if err != nil {
			tResp.Errors[name] = err
			continue
		}
		if !handled {
			continue
		}
		input := map[string]interface{}{"review": review}
		resp, err := c.backend.driver.Query(ctx, fmt.Sprintf("hooks.%s.deny", name), input)
		if err != nil {
			tResp.Errors[name] = err
			continue
		}
		for _, r := range resp.Results {
			if err := target.HandleViolation(r); err != nil {
				tResp.Errors[name] = err
				continue TargetLoop
			}
		}
		resp.Target = name
		responses[name] = resp
	}
	return responses, tResp
}

func (c *client) Audit(ctx context.Context) (types.Responses, *TargetResponse) {
	tResp := NewTargetResponse()
	responses := types.Responses{}
TargetLoop:
	for name, target := range c.targets {
		// Short-circuiting question applies here as well
		resp, err := c.backend.driver.Query(ctx, fmt.Sprintf("hooks.%s.audit", name), nil)
		if err != nil {
			tResp.Errors[name] = err
			continue
		}
		for _, r := range resp.Results {
			if err := target.HandleViolation(r); err != nil {
				tResp.Errors[name] = err
				continue TargetLoop
			}
		}
		resp.Target = name
		responses[name] = resp
	}
	return responses, tResp
}

func (c *client) Dump(ctx context.Context) (string, error) {
	return c.backend.driver.Dump(ctx)
}
