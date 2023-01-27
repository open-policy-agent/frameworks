package fake

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	apiconstraints "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/fake/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var ErrTesting = errors.New("test error")

func New(name string) *Driver {
	return &Driver{
		name:        name,
		code:        make(map[string]string),
		constraints: make(map[string]map[string]*unstructured.Unstructured),
	}
}

var _ drivers.Driver = &Driver{}

// Driver is a threadsafe Rego environment for compiling Rego in ConstraintTemplates,
// registering Constraints, and executing queries.
type Driver struct {
	name string

	errOnTemplateAdd      bool
	errOnTemplateRemove   bool
	errOnConstraintAdd    bool
	errOnConstraintRemove bool

	// mtx guards access to the storage and target maps.
	mtx sync.RWMutex

	// code maps the template name to the rejection statement to return.
	code map[string]string

	// constraints caches constraints for testing purposes.
	// stored as map[lowercase(kind)][name].
	constraints map[string]map[string]*unstructured.Unstructured
}

func (d *Driver) SetErrOnAddTemplate(raiseErr bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.errOnTemplateAdd = raiseErr
}

func (d *Driver) SetErrOnRemoveTemplate(raiseErr bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.errOnTemplateRemove = raiseErr
}

func (d *Driver) SetErrOnAddConstraint(raiseErr bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.errOnConstraintAdd = raiseErr
}

func (d *Driver) SetErrOnRemoveConstraint(raiseErr bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.errOnConstraintRemove = raiseErr
}

func (d *Driver) GetConstraintsForTemplate(template *templates.ConstraintTemplate) map[string]*unstructured.Unstructured {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	ret := make(map[string]*unstructured.Unstructured)
	for k, v := range d.constraints[template.Name] {
		ret[k] = v.DeepCopy()
	}
	return ret
}

func (d *Driver) GetTemplateCode() map[string]string {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	ret := make(map[string]string)
	for k, v := range d.code {
		ret[k] = v
	}
	return ret
}

// Name returns the name of the driver.
func (d *Driver) Name() string {
	return d.name
}

// AddTemplate adds templ to Driver. Normalizes modules into usable forms for
// use in queries.
func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	if len(ct.Spec.Targets) != 1 {
		return errors.New("wrong number of targets defined, only 1 target allowed")
	}
	var fakeCode templates.Code
	found := false
	for _, code := range ct.Spec.Targets[0].Code {
		if code.Engine != d.name {
			continue
		}
		fakeCode = code
		found = true
		break
	}
	if !found {
		return errors.New("SimplePolicy code not defined")
	}

	source, err := schema.GetSource(fakeCode)
	if err != nil {
		return err
	}

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.errOnTemplateAdd {
		return fmt.Errorf("%w: test error for add template", ErrTesting)
	}
	d.code[ct.GetName()] = source.RejectWith
	return nil
}

// RemoveTemplate removes all Compilers and Constraints for templ.
// Returns nil if templ does not exist.
func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.errOnTemplateRemove {
		return fmt.Errorf("%w: test error for remove template", ErrTesting)
	}
	delete(d.code, ct.GetName())
	delete(d.constraints, ct.GetName())
	return nil
}

// AddConstraint adds Constraint to storage. Used to validate state in tests.
func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.errOnConstraintAdd {
		return fmt.Errorf("%w: test error for add constraint", ErrTesting)
	}
	kind := strings.ToLower(constraint.GroupVersionKind().Kind)
	if _, ok := d.constraints[kind]; !ok {
		d.constraints[kind] = make(map[string]*unstructured.Unstructured)
	}

	d.constraints[kind][constraint.GetName()] = constraint.DeepCopy()

	return nil
}

// RemoveConstraint removes Constraint from Rego storage. Used to validate state in tests.
func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.errOnConstraintRemove {
		return fmt.Errorf("%w: test error for remove constraint", ErrTesting)
	}
	kind := strings.ToLower(constraint.GroupVersionKind().Kind)

	// if missing, consider the constraint removed
	if _, ok := d.constraints[kind]; !ok {
		return nil
	}

	delete(d.constraints[kind], constraint.GetName())

	return nil
}

// AddData should not be a thing that drivers handle.
func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	return nil
}

// RemoveData should not be a thing that drivers handle.
func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	return nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.Opt) (*drivers.QueryResponse, error) {
	results := []*types.Result{}
	for i := range constraints {
		constraint := constraints[i]
		result := &types.Result{
			Msg:        fmt.Sprintf("rejected by driver %s: %s", d.name, d.code[strings.ToLower(constraint.GetObjectKind().GroupVersionKind().Kind)]),
			Constraint: constraint,
			// TODO: the engine should not determine the enforcement action -- that does not work with CEL KEP
			EnforcementAction: apiconstraints.EnforcementActionDeny,
		}
		results = append(results, result)
	}

	return &drivers.QueryResponse{Results: results}, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	return "", nil
}
