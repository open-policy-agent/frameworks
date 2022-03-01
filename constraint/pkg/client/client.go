package client

import (
	"context"
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

// Client tracks ConstraintTemplates and Constraints for a set of Targets.
// Allows validating reviews against Constraints.
//
// Threadsafe.
// Assumes simultaneous calls for the same object do not happen. For example -
// concurrent calls to both update and remove a Template.
type Client struct {
	// driver contains the Rego runtime environments to run queries against.
	// Does not require mutex locking as Driver is threadsafe.
	driver drivers.Driver
	// targets are the targets supported by this Client.
	// Assumed to be constant after initialization.
	targets map[string]handler.TargetHandler

	// mtx guards access to the set of known Templates.
	// Write locks are only necessary when the set of known Templates is being
	// added to or removed from. Read locks are sufficient for Constraint operations
	// as they do not result in adding/removing Templates.
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

// createCRD creates the Template's CRD and validates the result.
func createCRD(templ *templates.ConstraintTemplate, target handler.TargetHandler) (*apiextensions.CustomResourceDefinition, error) {
	sch := crds.CreateSchema(templ, target)

	crd, err := crds.CreateCRD(templ, sch)
	if err != nil {
		return nil, err
	}

	err = crds.ValidateCRD(crd)
	if err != nil {
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

	templateName := templ.GetName()

	c.mtx.RLock()
	template, found := c.templates[templateName]
	c.mtx.RUnlock()

	if !found {
		template = &templateClient{
			constraints: make(map[string]*constraintClient),
		}

		c.mtx.Lock()
		c.templates[templateName] = template
		c.mtx.Unlock()
	}

	err = template.Update(templ, crd, target)
	if err != nil {
		return resp, err
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

	err := c.driver.RemoveTemplate(ctx, templ)
	if err != nil {
		return resp, err
	}

	templateName := templ.GetName()

	c.mtx.RLock()
	template, found := c.templates[templateName]
	c.mtx.RUnlock()

	if !found {
		return resp, nil
	}

	c.mtx.Lock()
	delete(c.templates, templateName)
	c.mtx.Unlock()

	for _, target := range template.getTargets() {
		resp.Handled[target.GetName()] = true
	}

	return resp, nil
}

// GetTemplate gets the currently recognized template.
func (c *Client) GetTemplate(templ *templates.ConstraintTemplate) (*templates.ConstraintTemplate, error) {
	template, err := c.getTemplate(templ.GetName())
	if err != nil {
		return nil, err
	}

	return template.getTemplate(), nil
}

func (c *Client) getTemplate(name string) (*templateClient, error) {
	c.mtx.RLock()
	t, ok := c.templates[name]
	c.mtx.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: template %q not found",
			ErrMissingConstraintTemplate, name)
	}

	return t, nil
}

// getTemplateEntry returns the template entry for a given constraint.
func (c *Client) getTemplateForKind(kind string) (*templateClient, error) {
	templateName := strings.ToLower(kind)

	return c.getTemplate(templateName)
}

// AddConstraint validates the constraint and, if valid, inserts it into OPA.
// On error, the responses return value will still be populated so that
// partial results can be analyzed.
func (c *Client) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) (*types.Responses, error) {
	resp := types.NewResponses()

	err := validateConstraintMetadata(constraint)
	if err != nil {
		return resp, err
	}

	template, err := c.getTemplateForKind(constraint.GetKind())
	if err != nil {
		return resp, err
	}

	targets := template.getTargets()

	changed, err := template.AddConstraint(constraint)
	if err != nil {
		return resp, err
	}

	if changed {
		err = c.driver.AddConstraint(ctx, constraint)
		if err != nil {
			return resp, err
		}
	}

	for _, target := range targets {
		resp.Handled[target.GetName()] = true
	}

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

	kind := constraint.GetKind()
	template, err := c.getTemplateForKind(kind)
	if err != nil {
		return resp, err
	}

	for _, target := range template.getTargets() {
		resp.Handled[target.GetName()] = true
	}

	template.RemoveConstraint(constraint.GetName())

	return resp, nil
}

// getConstraintNoLock gets the currently recognized constraint without the lock.
func (c *Client) getConstraint(kind, name string) (*unstructured.Unstructured, error) {
	if kind == "" {
		return nil, fmt.Errorf("%w: must specify kind", apiconstraints.ErrInvalidConstraint)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: must specify metadata.name", apiconstraints.ErrInvalidConstraint)
	}

	template, err := c.getTemplateForKind(kind)
	if err != nil {
		return nil, err
	}

	return template.GetConstraint(name)
}

// GetConstraint gets the currently recognized constraint.
func (c *Client) GetConstraint(constraint *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	return c.getConstraint(constraint.GetKind(), constraint.GetName())
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
		return fmt.Errorf("%w: wrong API Group for Constraint %q, got %q but need %q",
			apiconstraints.ErrInvalidConstraint, constraint.GetName(), gk.Group, apiconstraints.Group)
	}

	return nil
}

// validateConstraint is an internal function that allows us to toggle whether we use a read lock
// when validating a constraint.
func (c *Client) validateConstraint(constraint *unstructured.Unstructured) error {
	err := validateConstraintMetadata(constraint)
	if err != nil {
		return err
	}

	template, err := c.getTemplateForKind(constraint.GetKind())
	if err != nil {
		return err
	}

	return template.ValidateConstraint(constraint)
}

// ValidateConstraint returns an error if the constraint is not recognized or does not conform to
// the registered CRD for that constraint.
func (c *Client) ValidateConstraint(constraint *unstructured.Unstructured) error {
	return c.validateConstraint(constraint)
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

	var templateList []*templateClient

	c.mtx.RLock()
	for _, template := range c.templates {
		templateList = append(templateList, template)
	}
	c.mtx.RUnlock()

	for target, review := range reviews {
		var targetConstraints []*unstructured.Unstructured

		for _, template := range templateList {
			matchingConstraints := template.Matches(target, review)
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
