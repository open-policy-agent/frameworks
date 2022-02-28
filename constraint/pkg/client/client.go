package client

import (
	"context"
	"encoding/json"
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
	"k8s.io/utils/pointer"
)

type templateEntry struct {
	template *templates.ConstraintTemplate
	CRD      *apiextensions.CustomResourceDefinition
	Targets  []string
}

type Client struct {
	driver  drivers.Driver
	targets map[string]handler.TargetHandler

	// mtx guards access to both templates and constraints.
	mtx sync.RWMutex

	// templates is a map from a Template's name to its entry.
	templates   map[string]*templateEntry
	constraints map[string]map[string]*unstructured.Unstructured
	matchers    constraintMatchers
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

// validateTargets handles validating the targets section of the CT.
func (c *Client) validateTargets(templ *templates.ConstraintTemplate) (handler.TargetHandler, error) {
	if err := crds.ValidateTargets(templ); err != nil {
		return nil, err
	}

	targetSpec := &templ.Spec.Targets[0]
	targetHandler, found := c.targets[targetSpec.Target]

	if !found {
		knownTargets := c.knownTargets()

		return nil, fmt.Errorf("%w: target %q not recognized, known targets %v",
			clienterrors.ErrInvalidConstraintTemplate, targetSpec.Target, knownTargets)
	}

	return targetHandler, nil
}

func templateKeyFromConstraint(cst *unstructured.Unstructured) string {
	return strings.ToLower(cst.GetKind())
}

// createCRD creates the Template's CRD and validates the result.
func (c *Client) createCRD(templ *templates.ConstraintTemplate) (*apiextensions.CustomResourceDefinition, error) {
	targetHandler, err := c.ValidateConstraintTemplateBasic(templ)
	if err != nil {
		return nil, err
	}

	sch := crds.CreateSchema(templ, targetHandler)

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

	return c.createCRD(templ)
}

func (c *Client) ValidateConstraintTemplateBasic(templ *templates.ConstraintTemplate) (handler.TargetHandler, error) {
	kind := templ.Spec.CRD.Spec.Names.Kind
	if kind == "" {
		return nil, fmt.Errorf("%w: ConstraintTemplate %q does not specify CRD Kind",
			clienterrors.ErrInvalidConstraintTemplate, templ.GetName())
	}

	if !strings.EqualFold(templ.ObjectMeta.Name, kind) {
		return nil, fmt.Errorf("%w: the ConstraintTemplate's name %q is not equal to the lowercase of CRD's Kind: %q",
			clienterrors.ErrInvalidConstraintTemplate, templ.ObjectMeta.Name, strings.ToLower(kind))
	}

	targetHandler, err := c.validateTargets(templ)
	if err != nil {
		return nil, fmt.Errorf("failed to validate targets for template %s: %w", templ.Name, err)
	}

	return targetHandler, nil
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

	if err := c.driver.AddTemplate(templ); err != nil {
		return resp, err
	}

	cpy := templ.DeepCopy()
	cpy.Status = templates.ConstraintTemplateStatus{}

	crd, err := c.createCRD(templ)
	if err != nil {
		return resp, err
	}

	entry := &templateEntry{
		template: cpy,
		CRD:      crd,
		Targets:  []string{targetName},
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.templates[templ.GetName()] = entry

	kind := templ.Spec.CRD.Spec.Names.Kind
	if _, ok := c.constraints[kind]; !ok {
		c.constraints[kind] = make(map[string]*unstructured.Unstructured)
	}

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

	kind := templ.Spec.CRD.Spec.Names.Kind
	templateName := templ.GetName()
	delete(c.constraints, kind)
	delete(c.templates, templateName)
	c.matchers.RemoveKind(kind)

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

	ret := t.template.DeepCopy()
	return ret, nil
}

// getTemplateEntry returns the template entry for a given constraint.
func (c *Client) getTemplateEntry(constraint *unstructured.Unstructured, lock bool) (*templateEntry, error) {
	kind := constraint.GetKind()
	if kind == "" {
		return nil, fmt.Errorf("%w: kind missing from Constraint %q",
			crds.ErrInvalidConstraint, constraint.GetName())
	}

	group := constraint.GroupVersionKind().Group
	if group != apiconstraints.Group {
		return nil, fmt.Errorf("%w: wrong API Group for Constraint %q, got %q but need %q",
			crds.ErrInvalidConstraint, constraint.GetName(), group, apiconstraints.Group)
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
	for _, name := range entry.Targets {
		target, ok := c.targets[name]
		if !ok {
			return resp, fmt.Errorf("missing target %q", name)
		}

		targets = append(targets, target)
	}

	matchers, err := c.makeMatchers(targets, constraint)
	if err != nil {
		return resp, err
	}

	// return immediately if no change
	cached, err := c.getConstraintNoLock(constraint)
	if err == nil && constraintlib.SemanticEqual(cached, constraint) {
		for _, target := range entry.Targets {
			resp.Handled[target] = true
		}
		return resp, nil
	}

	err = c.validateConstraint(constraint, false)
	if err != nil {
		return resp, err
	}

	err = c.driver.AddConstraint(ctx, constraint)
	if err != nil {
		return nil, err
	}

	for _, target := range entry.Targets {
		resp.Handled[target] = true
	}

	c.matchers.Upsert(constraint, matchers)

	kind := constraint.GetKind()
	name := constraint.GetName()
	c.constraints[kind][name] = constraint.DeepCopy()

	return resp, nil
}

// RemoveConstraint removes a constraint from OPA. On error, the responses
// return value will still be populated so that partial results can be analyzed.
func (c *Client) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.removeConstraintNoLock(ctx, constraint)
}

func (c *Client) removeConstraintNoLock(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()

	err := validateConstraintMetadata(constraint)
	if err != nil {
		return resp, err
	}

	entry, err := c.getTemplateEntry(constraint, false)
	if err != nil {
		return resp, err
	}

	err = c.driver.RemoveConstraint(ctx, constraint)
	if err != nil {
		return nil, err
	}

	for _, target := range entry.Targets {
		resp.Handled[target] = true
	}

	c.matchers.RemoveConstraint(constraint)

	kind := constraint.GetKind()
	kindConstraints := c.constraints[kind]
	delete(kindConstraints, constraint.GetName())
	c.constraints[kind] = kindConstraints

	return resp, nil
}

// getConstraintNoLock gets the currently recognized constraint without the lock.
func (c *Client) getConstraintNoLock(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	err := validateConstraintMetadata(constraint)
	if err != nil {
		return nil, err
	}

	kind := constraint.GetKind()
	name := constraint.GetName()
	cstr, ok := c.constraints[kind][name]
	if !ok {
		return nil, fmt.Errorf("%w %v %q", ErrMissingConstraint, kind, name)
	}

	return cstr.DeepCopy(), nil
}

// GetConstraint gets the currently recognized constraint.
func (c *Client) GetConstraint(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.getConstraintNoLock(constraint)
}

func validateConstraintMetadata(constraint *unstructured.Unstructured) error {
	if constraint.GetName() == "" {
		return fmt.Errorf("%w: missing metadata.name", crds.ErrInvalidConstraint)
	}

	gk := constraint.GroupVersionKind()
	if gk.Kind == "" {
		return fmt.Errorf("%w: missing kind", crds.ErrInvalidConstraint)
	}

	if gk.Group != apiconstraints.Group {
		return fmt.Errorf("%w: incorrect group %q", crds.ErrInvalidConstraint, gk.Group)
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

	err = crds.ValidateCR(constraint, entry.CRD)
	if err != nil {
		return err
	}

	for _, targetName := range entry.Targets {
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

// Review makes sure the provided object satisfies all stored constraints.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) Review(ctx context.Context, obj interface{}, opts ...drivers.QueryOpt) (*types.Responses, error) {
	responses := types.NewResponses()
	errMap := make(clienterrors.ErrorMap)

	for name, target := range c.targets {
		// Short-circuiting question applies here as well
		handled, review, err := target.HandleReview(obj)
		if err != nil {
			errMap.Add(name, err)
			continue
		}
		if !handled {
			continue
		}

		resp, err := c.review(ctx, target, review, opts...)
		if err != nil {
			errMap.Add(name, err)
			continue
		}
		responses.ByTarget[name] = resp
	}

	if len(errMap) == 0 {
		return responses, nil
	}

	return responses, &errMap
}

func (c *Client) review(ctx context.Context, target handler.TargetHandler, review interface{}, opts ...drivers.QueryOpt) (*types.Response, error) {
	name := target.GetName()
	constraints, err := c.matchers.ConstraintsFor(name, review)
	if err != nil {
		// TODO(willbeason): This is where we'll make the determination about whether
		//  to continue, or just insert the autorejection into responses based on
		//  the Constraint's enforcementAction.
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrAutoreject, err)
	}

	input := map[string]interface{}{"review": review}

	var results []*types.Result
	var tracesBuilder strings.Builder

	results, trace, err := c.driver.Query(ctx, name, constraints, review, opts...)
	if err != nil {
		return nil, err
	}

	for _, violation := range results {
		err = target.HandleViolation(violation)
		if err != nil {
			return nil, err
		}

		if trace != nil {
			tracesBuilder.WriteString(*trace)
			tracesBuilder.WriteString("\n\n")
		}
	}

	inputJsn, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return nil, err
	}

	return &types.Response{
		Trace:   trace,
		Input:   pointer.String(string(inputJsn)),
		Target:  name,
		Results: results,
	}, nil
}

// Dump dumps the state of OPA to aid in debugging.
func (c *Client) Dump(ctx context.Context) (string, error) {
	return c.driver.Dump(ctx)
}

// knownTargets returns a sorted list of currently-known target names.
func (c *Client) knownTargets() []string {
	var knownTargets []string
	for known := range c.targets {
		knownTargets = append(knownTargets, known)
	}
	sort.Strings(knownTargets)

	return knownTargets
}

func (c *Client) makeMatchers(targets []handler.TargetHandler, constraint *unstructured.Unstructured) (map[string]constraintlib.Matcher, error) {
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
