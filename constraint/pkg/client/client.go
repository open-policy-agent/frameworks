package client

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	constraintlib "github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Client struct {
	driver  drivers.Driver
	targets map[string]handler.TargetHandler

	// mtx guards access to both templates and constraints.
	mtx sync.RWMutex

	// templates is a map from a Template's name to its entry.
	templates map[string]*templateClient
}

// getTargetHandler returns the TargetHandler for the Template, or an error if
// it does not exist.
//
// The set of targets is assumed to be constant.
func (c *Client) getTargetHandler(templ *templates.ConstraintTemplate) (handler.TargetHandler, error) {
	targetName, err := getTargetName(templ)
	if err != nil {
		return nil, err
	}

	targetHandler, found := c.targets[targetName]

	if !found {
		knownTargets := c.knownTargets()

		return nil, fmt.Errorf("%w: target %q not recognized, known targets %v",
			clienterrors.ErrInvalidConstraintTemplate, targetName, knownTargets)
	}

	return targetHandler, nil
}

func templateKeyFromConstraint(cst *unstructured.Unstructured) string {
	return strings.ToLower(cst.GetKind())
}

// createCRD creates the Template's CRD and validates the result.
func createCRD(templ *templates.ConstraintTemplate, target handler.TargetHandler) (*apiextensions.CustomResourceDefinition, error) {
	sch := crds.CreateSchema(templ, target)

	crd, err := crds.CreateCRD(templ, sch)
	if err != nil {
		return nil, err
	}

	if err := crds.ValidateCRD(crd); err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	return crd, nil
}

// CreateCRD creates a CRD from template.
func (c *Client) CreateCRD(templ *templates.ConstraintTemplate) (*apiextensions.CustomResourceDefinition, error) {
	if templ == nil {
		return nil, fmt.Errorf("%w: got nil ConstraintTemplate",
			clienterrors.ErrInvalidConstraintTemplate)
	}

	err := validateTemplateMetadata(templ)
	if err != nil {
		return nil, err
	}

	target, err := c.getTargetHandler(templ)
	if err != nil {
		return nil, err
	}

	return createCRD(templ, target)
}

func validateTemplateMetadata(templ *templates.ConstraintTemplate) error {
	kind := templ.Spec.CRD.Spec.Names.Kind
	if kind == "" {
		return fmt.Errorf("%w: ConstraintTemplate %q does not specify CRD Kind",
			clienterrors.ErrInvalidConstraintTemplate, templ.GetName())
	}

	if !strings.EqualFold(templ.ObjectMeta.Name, kind) {
		return fmt.Errorf("%w: the ConstraintTemplate's name %q is not equal to the lowercase of CRD's Kind: %q",
			clienterrors.ErrInvalidConstraintTemplate, templ.ObjectMeta.Name, strings.ToLower(kind))
	}

	return nil
}

// AddTemplate adds the template source code to OPA and registers the CRD with the client for
// schema validation on calls to AddConstraint. On error, the responses return value
// will still be populated so that partial results can be analyzed.
func (c *Client) AddTemplate(templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	// Return immediately if no change.
	targetName, err := getTargetName(templ)
	if err != nil {
		return resp, err
	}

	if cached, err := c.GetTemplate(templ); err == nil && cached.SemanticEqual(templ) {
		resp.Handled[targetName] = true
		return resp, nil
	}

	err = validateTemplateMetadata(templ)
	if err != nil {
		return resp, err
	}

	target, err := c.getTargetHandler(templ)
	if err != nil {
		return resp, err
	}

	crd, err := createCRD(templ, target)
	if err != nil {
		return resp, err
	}

	if err := c.driver.AddTemplate(templ); err != nil {
		return resp, err
	}

	cpy := templ.DeepCopy()
	cpy.Status = templates.ConstraintTemplateStatus{}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	template, found := c.templates[templ.GetName()]
	if !found {
		template = &templateClient{
			template:    cpy,
			constraints: make(map[string]*constraintClient),
			crd:         crd,
		}
	}

	matchers, err := template.makeMatchers([]handler.TargetHandler{target})
	if err != nil {
		return resp, err
	}

	template.updateMatchers(matchers)

	c.templates[templ.GetName()] = template

	resp.Handled[targetName] = true
	return resp, nil
}

func getTargetName(templ *templates.ConstraintTemplate) (string, error) {
	targets := templ.Spec.Targets

	switch len(targets) {
	case 0:
		return "", fmt.Errorf("%w: must declare exactly one target",
			clienterrors.ErrInvalidConstraintTemplate)
	case 1:
		return targets[0].Target, nil
	default:
		return "", fmt.Errorf("%w: must declare exactly one target",
			clienterrors.ErrInvalidConstraintTemplate)
	}
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry. Any constraints relying on the template will also be removed.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	// Driver is threadsafe, so it doesn't need to be guarded by a Mutex.
	err := c.driver.RemoveTemplate(ctx, templ)
	if err != nil {
		return resp, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	template, err := c.getTemplateNoLock(templ.GetName())
	if errors.Is(err, ErrMissingConstraintTemplate) {
		return resp, nil
	} else if err != nil {
		return resp, err
	}

	templateName := templ.GetName()
	delete(c.templates, templateName)

	for _, target := range template.Spec.Targets {
		resp.Handled[target.Target] = true
	}

	return resp, nil
}

// GetTemplate gets the currently recognized template.
func (c *Client) GetTemplate(templ *templates.ConstraintTemplate) (*templates.ConstraintTemplate, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.getTemplateNoLock(templ.GetName())
}

func (c *Client) getTemplateNoLock(name string) (*templates.ConstraintTemplate, error) {
	t, ok := c.templates[name]
	if !ok {
		return nil, fmt.Errorf("%w: template %q not found",
			ErrMissingConstraintTemplate, name)
	}

	return t.getTemplate(), nil
}

// getTemplateEntry returns the template entry for a given constraint.
func (c *Client) getTemplateEntry(constraint *unstructured.Unstructured, lock bool) (*templateClient, error) {
	kind := constraint.GetKind()
	if kind == "" {
		return nil, fmt.Errorf("%w: kind missing from Constraint %q",
			apiconstraints.ErrInvalidConstraint, constraint.GetName())
	}

	group := constraint.GroupVersionKind().Group
	if group != apiconstraints.Group {
		return nil, fmt.Errorf("%w: wrong API Group for Constraint %q, got %q but need %q",
			apiconstraints.ErrInvalidConstraint, constraint.GetName(), group, apiconstraints.Group)
	}

	if lock {
		c.mtx.RLock()
		defer c.mtx.RUnlock()
	}

	entry, ok := c.templates[templateKeyFromConstraint(constraint)]
	if !ok {
		var known []string
		for k := range c.templates {
			known = append(known, k)
		}

		return nil, fmt.Errorf("%w: Constraint kind %q is not recognized, known kinds %v",
			ErrMissingConstraintTemplate, kind, known)
	}

	return entry, nil
}

// AddConstraint validates the constraint and, if valid, inserts it into OPA.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	resp := types.NewResponses()
	entry, err := c.getTemplateEntry(constraint, false)
	if err != nil {
		return resp, err
	}

	var targets []handler.TargetHandler
	for _, name := range entry.Targets() {
		target, ok := c.targets[name]
		if !ok {
			return resp, fmt.Errorf("missing target %q", name)
		}

		targets = append(targets, target)
	}

	matchers, err := makeMatchers(targets, constraint)
	if err != nil {
		return resp, err
	}

	// return immediately if no change
	cached, err := c.getConstraintNoLock(constraint.GetKind(), constraint.GetName())
	if err == nil && constraintlib.SemanticEqual(cached, constraint) {
		for _, target := range entry.Targets() {
			resp.Handled[target] = true
		}
		return resp, nil
	}

	err = c.validateConstraint(constraint, false)
	if err != nil {
		return resp, err
	}

	kind := constraint.GetKind()
	templateName := strings.ToLower(kind)
	template, found := c.templates[templateName]
	if !found {
		return resp, fmt.Errorf("%w: %q", ErrMissingConstraintTemplate, templateName)
	}

	enforcementAction, err := apiconstraints.GetEnforcementAction(constraint)
	if err != nil {
		return resp, err
	}

	err = c.driver.AddConstraint(ctx, constraint)
	if err != nil {
		return resp, err
	}

	for _, target := range entry.Targets() {
		resp.Handled[target] = true
	}

	template.addConstraint(constraint, matchers, enforcementAction)

	return resp, nil
}

// RemoveConstraint removes a constraint from OPA. On error, the responses
// return value will still be populated so that partial results can be analyzed.
func (c *Client) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()

	err := validateConstraintMetadata(constraint)
	if err != nil {
		return resp, err
	}

	err = c.driver.RemoveConstraint(ctx, constraint)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	entry, err := c.getTemplateEntry(constraint, false)
	if err != nil {
		return resp, err
	}

	for _, target := range entry.Targets() {
		resp.Handled[target] = true
	}

	kind := constraint.GetKind()
	templateName := strings.ToLower(kind)
	template, ok := c.templates[templateName]
	if !ok {
		return resp, nil
	}
	template.removeConstraint(constraint.GetName())

	return resp, nil
}

// getConstraintNoLock gets the currently recognized constraint without the lock.
func (c *Client) getConstraintNoLock(kind, name string) (*unstructured.Unstructured, error) {
	if kind == "" {
		return nil, fmt.Errorf("%w: must specify kind", apiconstraints.ErrInvalidConstraint)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: must specify metadata.name", apiconstraints.ErrInvalidConstraint)
	}

	templateName := strings.ToLower(kind)
	template, ok := c.templates[templateName]
	if !ok {
		return nil, fmt.Errorf("%w %v %q", ErrMissingConstraintTemplate, kind, name)
	}

	return template.getConstraint(name)
}

// GetConstraint gets the currently recognized constraint.
func (c *Client) GetConstraint(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.getConstraintNoLock(constraint.GetKind(), constraint.GetName())
}

func validateConstraintMetadata(constraint *unstructured.Unstructured) error {
	if constraint.GetName() == "" {
		return fmt.Errorf("%w: missing metadata.name", apiconstraints.ErrInvalidConstraint)
	}

	gk := constraint.GroupVersionKind()
	if gk.Kind == "" {
		return fmt.Errorf("%w: missing kind", apiconstraints.ErrInvalidConstraint)
	}

	if gk.Group != apiconstraints.Group {
		return fmt.Errorf("%w: incorrect group %q", apiconstraints.ErrInvalidConstraint, gk.Group)
	}

	return nil
}

// validateConstraint is an internal function that allows us to toggle whether we use a read lock
// when validating a constraint.
func (c *Client) validateConstraint(constraint *unstructured.Unstructured, lock bool) error {
	err := validateConstraintMetadata(constraint)
	if err != nil {
		return err
	}

	entry, err := c.getTemplateEntry(constraint, lock)
	if err != nil {
		return err
	}

	err = entry.validateConstraint(constraint)
	if err != nil {
		return err
	}

	for _, targetName := range entry.Targets() {
		err = c.targets[targetName].ValidateConstraint(constraint)
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidateConstraint returns an error if the constraint is not recognized or does not conform to
// the registered CRD for that constraint.
func (c *Client) ValidateConstraint(constraint *unstructured.Unstructured) error {
	return c.validateConstraint(constraint, true)
}

// AddData inserts the provided data into OPA for every target that can handle the data.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddData(ctx context.Context, data interface{}) (*types.Responses, error) {
	// TODO(#189): Make AddData atomic across all Drivers/Targets.

	resp := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)
	for name, target := range c.targets {
		handled, key, processedData, err := target.ProcessData(data)
		if err != nil {
			errMap[name] = err
			continue
		}
		if !handled {
			continue
		}

		var cache handler.Cache
		if cacher, ok := target.(handler.Cacher); ok {
			cache = cacher.GetCache()
		}

		// Add to the target cache first because cache.Remove cannot fail. Thus, we
		// can prevent the system from getting into an inconsistent state.
		if cache != nil {
			err = cache.Add(key, processedData)
			if err != nil {
				// Use a different key than the driver to avoid clobbering errors.
				errMap[name] = err

				continue
			}
		}

		// paths passed to driver must be specific to the target to prevent key
		// collisions.
		targetPath := append([]string{name}, key...)
		err = c.driver.AddData(ctx, targetPath, processedData)
		if err != nil {
			errMap[name] = err

			if cache != nil {
				cache.Remove(key)
			}
			continue
		}

		resp.Handled[name] = true
	}

	if len(errMap) == 0 {
		return resp, nil
	}
	return resp, &errMap
}

// RemoveData removes data from OPA for every target that can handle the data.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) RemoveData(ctx context.Context, data interface{}) (*types.Responses, error) {
	resp := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)
	for target, h := range c.targets {
		handled, relPath, _, err := h.ProcessData(data)
		if err != nil {
			errMap[target] = err
			continue
		}
		if !handled {
			continue
		}

		targetPath := append([]string{target}, relPath...)
		err = c.driver.RemoveData(ctx, targetPath)
		if err != nil {
			errMap[target] = err
			continue
		}

		resp.Handled[target] = true

		if cacher, ok := h.(handler.Cacher); ok {
			cache := cacher.GetCache()

			cache.Remove(relPath)
		}
	}

	if len(errMap) == 0 {
		return resp, nil
	}

	return resp, &errMap
}

// Review makes sure the provided object satisfies all stored constraints.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) Review(ctx context.Context, obj interface{}, opts ...drivers.QueryOpt) (*types.Responses, error) {
	responses := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)

	ignoredTargets := make(map[string]bool)
	reviews := make(map[string]interface{})
	for name, target := range c.targets {
		handled, review, err := target.HandleReview(obj)
		if err != nil {
			errMap.Add(name, err)
			continue
		}

		if !handled {
			ignoredTargets[name] = true
			continue
		}

		reviews[name] = review
	}

	constraintsByTarget := make(map[string][]*unstructured.Unstructured)
	autorejections := make(map[string][]constraintMatchResult)

	for target, review := range reviews {
		var targetConstraints []*unstructured.Unstructured

		for _, template := range c.templates {
			matchingConstraints := template.matches(target, review)
			for _, matchResult := range matchingConstraints {
				if matchResult.error == nil {
					targetConstraints = append(targetConstraints, matchResult.constraint)
				} else {
					autorejections[target] = append(autorejections[target], matchResult)
				}
			}
		}
		constraintsByTarget[target] = targetConstraints
	}

	for target, review := range reviews {
		constraints := constraintsByTarget[target]

		resp, err := c.review(ctx, target, constraints, review, opts...)
		if err != nil {
			errMap.Add(target, err)
			continue
		}

		for _, autorejection := range autorejections[target] {
			resp.AddResult(autorejection.ToResult())
		}

		// Ensure deterministic result ordering.
		resp.Sort()

		responses.ByTarget[target] = resp
	}

	if len(errMap) == 0 {
		return responses, nil
	}

	return responses, &errMap
}

func (c *Client) review(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) (*types.Response, error) {
	var results []*types.Result
	var tracesBuilder strings.Builder

	results, trace, err := c.driver.Query(ctx, target, constraints, review, opts...)
	if err != nil {
		return nil, err
	}

	if trace != nil {
		tracesBuilder.WriteString(*trace)
		tracesBuilder.WriteString("\n\n")
	}

	return &types.Response{
		Trace:   trace,
		Target:  target,
		Results: results,
	}, nil
}

// Dump dumps the state of OPA to aid in debugging.
func (c *Client) Dump(ctx context.Context) (string, error) {
	return c.driver.Dump(ctx)
}

// knownTargets returns a sorted list of known target names.
func (c *Client) knownTargets() []string {
	var knownTargets []string
	for known := range c.targets {
		knownTargets = append(knownTargets, known)
	}
	sort.Strings(knownTargets)

	return knownTargets
}

func makeMatchers(targets []handler.TargetHandler, constraint *unstructured.Unstructured) (map[string]constraintlib.Matcher, error) {
	result := make(map[string]constraintlib.Matcher)
	errs := clienterrors.ErrorMap{}

	for _, target := range targets {
		name := target.GetName()
		matcher, err := target.ToMatcher(constraint)
		if err != nil {
			errs.Add(name, err)
		}

		result[name] = matcher
	}

	if len(errs) > 0 {
		return nil, &errs
	}

	return result, nil
}
