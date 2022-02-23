package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/crds"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	constraintlib "github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	mtx       sync.RWMutex
	templates map[templateKey]*templateEntry
	// TODO: https://github.com/open-policy-agent/frameworks/issues/187
	constraints map[schema.GroupKind]map[string]*unstructured.Unstructured
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
		_, err = c.driver.RemoveData(ctx, targetPath)
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

// createTemplatePath returns the package path for a given template: templates.<target>.<name>.
func createTemplatePath(name string) string {
	return fmt.Sprintf(`templates["%s"]`, name)
}

// validateTargets handles validating the targets section of the CT.
func (c *Client) validateTargets(templ *templates.ConstraintTemplate) (*templates.Target, handler.TargetHandler, error) {
	if err := crds.ValidateTargets(templ); err != nil {
		return nil, nil, err
	}

	targetSpec := &templ.Spec.Targets[0]
	targetHandler, found := c.targets[targetSpec.Target]

	if !found {
		knownTargets := c.knownTargets()

		return nil, nil, fmt.Errorf("%w: target %q not recognized, known targets %v",
			clienterrors.ErrInvalidConstraintTemplate, targetSpec.Target, knownTargets)
	}

	return targetSpec, targetHandler, nil
}

type templateKey string

type keyableArtifact interface {
	Key() templateKey
}

var _ keyableArtifact = &basicCTArtifacts{}

func templateKeyFromConstraint(cst *unstructured.Unstructured) templateKey {
	return templateKey(strings.ToLower(cst.GetKind()))
}

// rawCTArtifacts have no processing and are only useful for looking things up
// from the cache.
type rawCTArtifacts struct {
	// template is the template itself
	template *templates.ConstraintTemplate
}

func (a *rawCTArtifacts) Key() templateKey {
	return templateKey(a.template.GetName())
}

// createRawTemplateArtifacts creates the "free" artifacts for a template, avoiding more
// complex tasks like rewriting Rego. Provides minimal validation.
func (c *Client) createRawTemplateArtifacts(templ *templates.ConstraintTemplate) (*rawCTArtifacts, error) {
	if templ.GetName() == "" {
		return nil, fmt.Errorf("%w: missing name", clienterrors.ErrInvalidConstraintTemplate)
	}

	return &rawCTArtifacts{template: templ}, nil
}

// basicCTArtifacts are the artifacts created by processing a constraint template
// that require little compute effort.
type basicCTArtifacts struct {
	rawCTArtifacts

	// namePrefix is the name prefix by which the modules will be identified during create / delete
	// calls to the drivers.Driver interface.
	namePrefix string

	// gk is the groupKind of the constraints the template creates
	gk schema.GroupKind

	// crd is the CustomResourceDefinition created from the CT.
	crd *apiextensions.CustomResourceDefinition

	// targetHandler is the target handler indicated by the CT.  This isn't generated, but is used by
	// consumers of createTemplateArtifacts
	targetHandler handler.TargetHandler

	// targetSpec is the target-oriented portion of a CT's Spec field.
	targetSpec *templates.Target
}

func (a *basicCTArtifacts) CRD() *apiextensions.CustomResourceDefinition {
	return a.crd
}

// createBasicTemplateArtifacts creates the low-cost artifacts for a template, avoiding more
// complex tasks like rewriting Rego.
func (c *Client) createBasicTemplateArtifacts(templ *templates.ConstraintTemplate) (*basicCTArtifacts, error) {
	rawArtifacts, err := c.createRawTemplateArtifacts(templ)
	if err != nil {
		return nil, err
	}
	targetSpec, targetHandler, err := c.ValidateConstraintTemplateBasic(templ)
	if err != nil {
		return nil, err
	}

	sch := crds.CreateSchema(templ, targetHandler)

	crd, err := crds.CreateCRD(templ, sch)
	if err != nil {
		return nil, err
	}

	if err = crds.ValidateCRD(crd); err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	entryPointPath := createTemplatePath(templ.Spec.CRD.Spec.Names.Kind)

	return &basicCTArtifacts{
		rawCTArtifacts: *rawArtifacts,
		gk:             schema.GroupKind{Group: crd.Spec.Group, Kind: crd.Spec.Names.Kind},
		crd:            crd,
		targetHandler:  targetHandler,
		targetSpec:     targetSpec,
		namePrefix:     entryPointPath,
	}, nil
}

// CreateCRD creates a CRD from template.
func (c *Client) CreateCRD(templ *templates.ConstraintTemplate) (*apiextensions.CustomResourceDefinition, error) {
	if templ == nil {
		return nil, fmt.Errorf("%w: got nil ConstraintTemplate",
			clienterrors.ErrInvalidConstraintTemplate)
	}

	artifacts, err := c.createBasicTemplateArtifacts(templ)
	if err != nil {
		return nil, err
	}
	return artifacts.crd, nil
}

func (c *Client) ValidateConstraintTemplateBasic(templ *templates.ConstraintTemplate) (*templates.Target, handler.TargetHandler, error) {
	kind := templ.Spec.CRD.Spec.Names.Kind
	if kind == "" {
		return nil, nil, fmt.Errorf("%w: ConstraintTemplate %q does not specify CRD Kind",
			clienterrors.ErrInvalidConstraintTemplate, templ.GetName())
	}

	if !strings.EqualFold(templ.ObjectMeta.Name, kind) {
		return nil, nil, fmt.Errorf("%w: the ConstraintTemplate's name %q is not equal to the lowercase of CRD's Kind: %q",
			clienterrors.ErrInvalidConstraintTemplate, templ.ObjectMeta.Name, strings.ToLower(kind))
	}

	targetSpec, targetHandler, err := c.validateTargets(templ)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate targets for template %s: %w", templ.Name, err)
	}

	return targetSpec, targetHandler, nil
}

func (c *Client) ValidateConstraintTemplate(templ *templates.ConstraintTemplate) error {
	if templ == nil {
		return fmt.Errorf(`%w: ConstraintTemplate is nil`,
			clienterrors.ErrInvalidConstraintTemplate)
	}

	if _, _, err := c.ValidateConstraintTemplateBasic(templ); err != nil {
		return err
	}

	if dr, ok := c.driver.(*local.Driver); ok {
		_, _, err := dr.ValidateConstraintTemplate(templ)
		return err
	}

	return fmt.Errorf("driver %T is not supported", c.driver)
}

// AddTemplate adds the template source code to OPA and registers the CRD with the client for
// schema validation on calls to AddConstraint. On error, the responses return value
// will still be populated so that partial results can be analyzed.
func (c *Client) AddTemplate(templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	basicArtifacts, err := c.createBasicTemplateArtifacts(templ)
	if err != nil {
		return resp, err
	}

	// return immediately if no change
	if cached, err := c.GetTemplate(templ); err == nil && cached.SemanticEqual(templ) {
		resp.Handled[basicArtifacts.targetHandler.GetName()] = true
		return resp, nil
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if err = c.driver.AddTemplate(templ); err != nil {
		return resp, err
	}
	cpy := templ.DeepCopy()
	cpy.Status = templates.ConstraintTemplateStatus{}
	c.templates[basicArtifacts.Key()] = &templateEntry{
		template: cpy,
		CRD:      basicArtifacts.crd,
		Targets:  []string{basicArtifacts.targetHandler.GetName()},
	}

	gk := basicArtifacts.gk
	if _, ok := c.constraints[gk]; !ok {
		c.constraints[gk] = make(map[string]*unstructured.Unstructured)
	}

	resp.Handled[basicArtifacts.targetHandler.GetName()] = true
	return resp, nil
}

// RemoveTemplate removes the template source code from OPA and removes the CRD from the validation
// registry. Any constraints relying on the template will also be removed.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) (*types.Responses, error) {
	resp := types.NewResponses()

	rawArtifacts, err := c.createRawTemplateArtifacts(templ)
	if err != nil {
		return resp, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	template, err := c.getTemplateNoLock(rawArtifacts.Key())
	if err != nil {
		if errors.Is(err, ErrMissingConstraintTemplate) {
			return resp, nil
		}
		return resp, err
	}

	artifacts, err := c.createBasicTemplateArtifacts(template)
	if err != nil {
		return resp, err
	}

	gk := artifacts.gk
	for _, cstr := range c.constraints[gk] {
		r, err := c.removeConstraintNoLock(cstr)
		if err != nil {
			return r, err
		}
	}

	err = c.driver.RemoveTemplate(ctx, templ)
	if err != nil {
		return resp, err
	}

	delete(c.constraints, gk)
	delete(c.templates, artifacts.Key())
	c.matchers.RemoveKind(gk.Kind)
	resp.Handled[artifacts.targetHandler.GetName()] = true
	return resp, nil
}

// GetTemplate gets the currently recognized template.
func (c *Client) GetTemplate(templ *templates.ConstraintTemplate) (*templates.ConstraintTemplate, error) {
	artifacts, err := c.createRawTemplateArtifacts(templ)
	if err != nil {
		return nil, err
	}

	c.mtx.RLock()
	defer c.mtx.RUnlock()
	return c.getTemplateNoLock(artifacts.Key())
}

func (c *Client) getTemplateNoLock(key templateKey) (*templates.ConstraintTemplate, error) {
	t, ok := c.templates[key]
	if !ok {
		return nil, fmt.Errorf("%w: template for %q not found",
			ErrMissingConstraintTemplate, key)
	}

	ret := t.template.DeepCopy()
	return ret, nil
}

// createConstraintSubPath returns the key where we will store the constraint
// for each target: cluster.<group>.<kind>.<name>.
func createConstraintSubPath(constraint *unstructured.Unstructured) (string, error) {
	if constraint.GetName() == "" {
		return "", fmt.Errorf("%w: missing name", crds.ErrInvalidConstraint)
	}

	gvk := constraint.GroupVersionKind()
	if gvk.Group == "" {
		return "", fmt.Errorf("%w: empty group for constrant %q",
			crds.ErrInvalidConstraint, constraint.GetName())
	}

	if gvk.Kind == "" {
		return "", fmt.Errorf("%w: empty kind for constraint %q",
			crds.ErrInvalidConstraint, constraint.GetName())
	}

	return path.Join(createConstraintGKSubPath(gvk.GroupKind()), constraint.GetName()), nil
}

// createConstraintGKPath returns the subpath for given a constraint GK.
func createConstraintGKSubPath(gk schema.GroupKind) string {
	return "/" + path.Join("cluster", gk.Group, gk.Kind)
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
			known = append(known, string(k))
		}

		return nil, fmt.Errorf("%w: Constraint kind %q is not recognized, known kinds %v",
			ErrMissingConstraintTemplate, kind, known)
	}

	return entry, nil
}

// AddConstraint validates the constraint and, if valid, inserts it into OPA.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddConstraint(constraint *unstructured.Unstructured) (*types.Responses, error) {
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

	subPath, err := createConstraintSubPath(constraint)
	if err != nil {
		return resp, fmt.Errorf("creating Constraint subpath: %w", err)
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

	for _, target := range entry.Targets {
		resp.Handled[target] = true
	}

	c.matchers.Upsert(constraint, matchers)

	c.constraints[constraint.GroupVersionKind().GroupKind()][subPath] = constraint.DeepCopy()

	return resp, nil
}

// RemoveConstraint removes a constraint from OPA. On error, the responses
// return value will still be populated so that partial results can be analyzed.
func (c *Client) RemoveConstraint(constraint *unstructured.Unstructured) (*types.Responses, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.removeConstraintNoLock(constraint)
}

func (c *Client) removeConstraintNoLock(constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()
	entry, err := c.getTemplateEntry(constraint, false)
	if err != nil {
		return resp, err
	}

	subPath, err := createConstraintSubPath(constraint)
	if err != nil {
		return resp, err
	}

	for _, target := range entry.Targets {
		resp.Handled[target] = true
	}

	c.matchers.RemoveConstraint(constraint)

	delete(c.constraints[constraint.GroupVersionKind().GroupKind()], subPath)
	return resp, nil
}

// getConstraintNoLock gets the currently recognized constraint without the lock.
func (c *Client) getConstraintNoLock(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	subPath, err := createConstraintSubPath(constraint)
	if err != nil {
		return nil, err
	}

	gk := constraint.GroupVersionKind().GroupKind()
	cstr, ok := c.constraints[gk][subPath]
	if !ok {
		return nil, fmt.Errorf("%w %v %q",
			ErrMissingConstraint, gk, constraint.GetName())
	}
	return cstr.DeepCopy(), nil
}

// GetConstraint gets the currently recognized constraint.
func (c *Client) GetConstraint(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.getConstraintNoLock(constraint)
}

// validateConstraint is an internal function that allows us to toggle whether we use a read lock
// when validating a constraint.
func (c *Client) validateConstraint(constraint *unstructured.Unstructured, lock bool) error {
	entry, err := c.getTemplateEntry(constraint, lock)
	if err != nil {
		return err
	}

	err = crds.ValidateCR(constraint, entry.CRD)
	if err != nil {
		return err
	}

	for _, targetName := range entry.Targets {
		err := c.targets[targetName].ValidateConstraint(constraint)
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
		handled, key, review, err := target.HandleReview(obj)
		if err != nil {
			return nil, err
		}
		if !handled {
			continue
		}

		resp, err := c.review(ctx, target, key, review, opts...)
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

func (c *Client) review(ctx context.Context, target handler.TargetHandler, key handler.Key, review interface{}, opts ...drivers.QueryOpt) (*types.Response, error) {
	name := target.GetName()
	constraints, err := c.matchers.ConstraintsFor(name, review)
	if err != nil {
		// TODO(willbeason): This is where we'll make the determination about whether
		//  to continue, or just insert the autorejection into responses based on
		//  the Constraint's enforcementAction.
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrAutoreject, err)
	}

	input := map[string]interface{}{"review": review}

	var resultSet rego.ResultSet
	var tracesBuilder strings.Builder
	for _, constraint := range constraints {
		result, trace, err := c.driver.Query(ctx, name, constraint, key, review, opts...)
		if err != nil {
			return nil, err
		}
		resultSet = append(resultSet, result...)

		if trace != nil {
			tracesBuilder.WriteString(*trace)
			tracesBuilder.WriteString("\n\n")
		}
	}

	results, err := local.ToResults(target, resultSet)
	if err != nil {
		return nil, err
	}

	inputJsn, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return nil, err
	}

	trace := pointer.String(tracesBuilder.String())
	if len(*trace) == 0 {
		trace = nil
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
