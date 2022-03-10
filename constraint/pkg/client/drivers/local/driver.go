package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/print"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

const (
	libRoot   = "data.lib"
	violation = "violation"
)

var _ drivers.Driver = &Driver{}

// Driver is a threadsafe Rego environment for compiling Rego in ConstraintTemplates,
// registering Constraints, and executing queries.
type Driver struct {
	// compilers is a store of Rego Compilers for each Template.
	compilers Compilers

	// mtx guards access to the storage and target maps.
	mtx sync.RWMutex

	// storage is a map from target name to the Rego data store for Constraints
	// and objects used in referential Constraints.
	// storage internally uses mutexes to guard reads and writes during
	// transactions and queries, so we don't need to explicitly guard individual
	// Stores with mutexes.
	storage map[string]storage.Store

	// targets is a map from each Template's kind to the targets for that Template.
	targets map[string][]string

	// traceEnabled is whether tracing is enabled for Rego queries by default.
	// If enabled, individual queries cannot disable tracing.
	traceEnabled bool

	// printEnabled is whether print statements are allowed in Rego. If disabled,
	// print statements are removed from modules at compile-time.
	printEnabled bool

	// printHook specifies where to send the output of Rego print() statements.
	printHook print.Hook

	// providerCache allows Rego to read from external_data in Rego queries.
	providerCache *externaldata.ProviderCache
}

// AddTemplate adds templ to Driver. Normalizes modules into usable forms for
// use in queries.
func (d *Driver) AddTemplate(ctx context.Context, templ *templates.ConstraintTemplate) error {
	var targets []string
	for _, target := range templ.Spec.Targets {
		_, err := d.getStorage(ctx, target.Target)
		if err != nil {
			return err
		}
		targets = append(targets, target.Target)
	}

	kind := templ.Spec.CRD.Spec.Names.Kind

	d.mtx.Lock()
	d.targets[kind] = targets
	d.mtx.Unlock()

	return d.compilers.addTemplate(templ, d.printEnabled)
}

// RemoveTemplate removes all Compilers and Constraints for templ.
// Returns nil if templ does not exist.
func (d *Driver) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) error {
	kind := templ.Spec.CRD.Spec.Names.Kind

	d.compilers.removeTemplate(kind)

	constraintParent := storage.Path{"constraint", kind}

	d.mtx.Lock()
	delete(d.targets, kind)
	d.mtx.Unlock()

	// We aren't modifying the map, only the underlying storage objects so we
	// don't need a write lock.
	d.mtx.RLock()
	defer d.mtx.RUnlock()
	for target := range d.storage {
		err := d.removeData(ctx, target, constraintParent)
		if err != nil {
			return err
		}
	}

	return nil
}

// AddConstraint adds Constraint to Rego storage. Future calls to Query will
// be evaluated against Constraint if the Constraint's key is passed.
func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	params, _, err := unstructured.NestedFieldNoCopy(constraint.Object, "spec", "parameters")
	if err != nil {
		return fmt.Errorf("%w: %v", constraints.ErrInvalidConstraint, err)
	}

	// default .spec.parameters so that we don't need to default this in Rego.
	if params == nil {
		params = make(map[string]interface{})
	}

	key := drivers.ConstraintKeyFrom(constraint)

	d.mtx.RLock()
	defer d.mtx.RUnlock()
	targets := d.targets[key.Kind]

	for _, target := range targets {
		err := d.addData(ctx, target, key.StoragePath(), params)
		if err != nil {
			return err
		}
	}

	return nil
}

// RemoveConstraint removes Constraint from Rego storage. Future calls to Query
// will not be evaluated against the constraint. Queries which specify the
// constraint's key will silently not evaluate the Constraint.
func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	key := drivers.ConstraintKeyFrom(constraint)

	d.mtx.RLock()
	defer d.mtx.RUnlock()
	targets := d.targets[key.Kind]

	for _, target := range targets {
		err := d.removeData(ctx, target, key.StoragePath())
		if err != nil {
			return err
		}
	}

	return nil
}

// AddData adds data to Rego storage at data.inventory.path.
func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	path = inventoryPath(path)
	return d.addData(ctx, target, path, data)
}

// RemoveData deletes data from Rego storage at data.inventory.path.
func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	path = inventoryPath(path)
	return d.removeData(ctx, target, path)
}

// eval runs a query against compiler.
// path is the path to evaluate.
// input is the already-parsed Rego Value to use as input.
// Returns the Rego results, the trace if requested, or an error if there was
// a problem executing the query.
func (d *Driver) eval(ctx context.Context, compiler *ast.Compiler, target string, path []string, input ast.Value, opts ...drivers.QueryOpt) (rego.ResultSet, *string, error) {
	cfg := &drivers.QueryCfg{}
	for _, opt := range opts {
		opt(cfg)
	}

	queryPath := strings.Builder{}
	queryPath.WriteString("data")
	for _, p := range path {
		queryPath.WriteString(".")
		queryPath.WriteString(p)
	}

	store, err := d.getStorage(ctx, target)
	if err != nil {
		return nil, nil, err
	}

	args := []func(*rego.Rego){
		rego.Compiler(compiler),
		rego.Store(store),
		rego.ParsedInput(input),
		rego.Query(queryPath.String()),
		rego.EnablePrintStatements(d.printEnabled),
		rego.PrintHook(d.printHook),
	}

	buf := topdown.NewBufferTracer()
	if d.traceEnabled || cfg.TracingEnabled {
		args = append(args, rego.QueryTracer(buf))
	}

	r := rego.New(args...)
	res, err := r.Eval(ctx)

	var t *string
	if d.traceEnabled || cfg.TracingEnabled {
		b := &bytes.Buffer{}
		topdown.PrettyTrace(b, *buf)
		t = pointer.StringPtr(b.String())
	}

	return res, t, err
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {
	if len(constraints) == 0 {
		return nil, nil, nil
	}

	constraintsByKind := toConstraintsByKind(constraints)

	traceBuilder := strings.Builder{}
	constraintsMap := drivers.KeyMap(constraints)
	path := []string{"hooks", "violation[result]"}

	var results []*types.Result

	// Round-trip review through JSON so that the review object is round-tripped
	// once per call to Query instead of once per compiler.
	reviewMap, err := toInterfaceMap(review)
	if err != nil {
		return nil, nil, err
	}

	for kind, kindConstraints := range constraintsByKind {
		compiler := d.compilers.getCompiler(target, kind)
		if compiler == nil {
			// The Template was just removed, so the Driver is in an inconsistent
			// state with Client. Raise this as an error rather than attempting to
			// continue.
			return nil, nil, fmt.Errorf("missing Template %q for target %q", kind, target)
		}

		// Parse input into an ast.Value to avoid round-tripping through JSON when
		// possible.
		parsedInput, err := toParsedInput(target, kindConstraints, reviewMap)
		if err != nil {
			return nil, nil, err
		}

		resultSet, trace, err := d.eval(ctx, compiler, target, path, parsedInput, opts...)
		if err != nil {
			resultSet = make(rego.ResultSet, 0, len(kindConstraints))
			for _, constraint := range kindConstraints {
				resultSet = append(resultSet, rego.Result{
					Bindings: map[string]interface{}{
						"result": map[string]interface{}{
							"msg": err.Error(),
							"key": map[string]interface{}{
								"kind": constraint.GetKind(),
								"name": constraint.GetName(),
							},
						},
					},
				})
			}
		}
		if trace != nil {
			traceBuilder.WriteString(*trace)
		}

		kindResults, err := drivers.ToResults(constraintsMap, resultSet)
		if err != nil {
			return nil, nil, err
		}

		results = append(results, kindResults...)
	}

	traceString := traceBuilder.String()
	if len(traceString) != 0 {
		return results, &traceString, nil
	}

	return results, nil, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	dt := make(map[string]map[string]rego.ResultSet)

	compilers := d.compilers.list()
	for targetName, targetCompilers := range compilers {
		targetData := make(map[string]rego.ResultSet)

		for kind, compiler := range targetCompilers {
			rs, _, err := d.eval(ctx, compiler, targetName, []string{"data"}, nil)
			if err != nil {
				return "", err
			}
			targetData[kind] = rs
		}

		dt[targetName] = targetData
	}

	resp := map[string]interface{}{
		"data": dt,
	}

	b, err := json.MarshalIndent(resp, "", "   ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// templateLibPrefix returns the new lib prefix for the libs that are specified in the CT.
func templateLibPrefix(name string) string {
	return fmt.Sprintf("libs.%s", name)
}

// parseModule parses the module and also fails empty modules.
func parseModule(rego string) (*ast.Module, error) {
	module, err := ast.ParseModule(templatePath, rego)
	if err != nil {
		return nil, err
	}

	if module == nil {
		return nil, fmt.Errorf("%w: module %q is empty",
			clienterrors.ErrInvalidModule, templatePath)
	}

	return module, nil
}

// rewriteModulePackage rewrites the module's package path to path.
func rewriteModulePackage(module *ast.Module) error {
	pathParts := ast.Ref([]*ast.Term{ast.VarTerm(templatePath)})

	packageRef := ast.Ref([]*ast.Term{ast.VarTerm("data")})
	newPath := packageRef.Extend(pathParts)
	module.Package.Path = newPath
	return nil
}

// requireModuleRules makes sure the module contains all of the specified
// requiredRules.
func requireModuleRules(module *ast.Module, requiredRules map[string]struct{}) error {
	ruleSets := make(map[string]struct{}, len(module.Rules))
	for _, rule := range module.Rules {
		ruleSets[string(rule.Head.Name)] = struct{}{}
	}

	var missing []string
	for name := range requiredRules {
		_, ok := ruleSets[name]
		if !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		return fmt.Errorf("%w: missing required rules: %v",
			clienterrors.ErrInvalidModule, missing)
	}

	return nil
}

func toInterfaceMap(obj interface{}) (map[string]interface{}, error) {
	jsn, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	err = json.Unmarshal(jsn, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func toKeySlice(constraints []*unstructured.Unstructured) []interface{} {
	var keys []interface{}
	for _, constraint := range constraints {
		key := drivers.ConstraintKeyFrom(constraint)
		keys = append(keys, map[string]interface{}{
			"kind": key.Kind,
			"name": key.Name,
		})
	}

	return keys
}

func toConstraintsByKind(constraints []*unstructured.Unstructured) map[string][]*unstructured.Unstructured {
	constraintsByKind := make(map[string][]*unstructured.Unstructured)
	for _, constraint := range constraints {
		kind := constraint.GetKind()
		constraintsByKind[kind] = append(constraintsByKind[kind], constraint)
	}

	return constraintsByKind
}

func toParsedInput(target string, constraints []*unstructured.Unstructured, review map[string]interface{}) (ast.Value, error) {
	// Store constraint keys in a format InterfaceToValue does not need to
	// round-trip through JSON.
	constraintKeys := toKeySlice(constraints)

	input := map[string]interface{}{
		"target":      target,
		"constraints": constraintKeys,
		"review":      review,
	}

	// Parse input into an ast.Value to avoid round-tripping through JSON when
	// possible.
	return ast.InterfaceToValue(input)
}

func inventoryPath(path []string) storage.Path {
	return append([]string{"external"}, path...)
}

func (d *Driver) addData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	if len(path) == 0 {
		// Sanity-check path.
		// This would overwrite "data", erasing all Constraints and stored objects.
		return fmt.Errorf("%w: path must contain at least one path element: %+v", clienterrors.ErrPathInvalid, path)
	}

	store, err := d.getStorage(ctx, target)
	if err != nil {
		return err
	}

	// Initiate a new transaction. Since this is a write-transaction, it blocks
	// all other reads and writes, which includes running queries. If a transaction
	// is successfully created, all code paths must either Abort or Commit the
	// transaction to unblock queries and other writes.
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	// We can't write to a location if its parent doesn't exist.
	// Thus, we check to see if anything already exists at the path.
	_, err = store.Read(ctx, txn, path)
	if storage.IsNotFound(err) {
		// Insert an empty object at the path's parent so its parents are
		// recursively created.
		parent := path[:len(path)-1]
		err = storage.MakeDir(ctx, store, txn, parent)
		if err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("%w: unable to make directory: %v", clienterrors.ErrWrite, err)
		}
	} else if err != nil {
		// We weren't able to read from storage - something serious is likely wrong.
		store.Abort(ctx, txn)
		return fmt.Errorf("%w: %v", clienterrors.ErrRead, err)
	}

	err = store.Write(ctx, txn, storage.AddOp, path, data)
	if err != nil {
		store.Abort(ctx, txn)
		return fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	return nil
}

func (d *Driver) removeData(ctx context.Context, target string, path storage.Path) error {
	store, err := d.getStorage(ctx, target)
	if err != nil {
		return err
	}

	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	err = store.Write(ctx, txn, storage.RemoveOp, path, interface{}(nil))
	if err != nil {
		store.Abort(ctx, txn)
		if storage.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("%w: unable to remove data: %v", clienterrors.ErrWrite, err)
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	return nil
}

// getStorage gets the Rego Store for a target, or instantiates it if it does not
// already exist.
// Instantiates data.inventory for the store.
func (d *Driver) getStorage(ctx context.Context, target string) (storage.Store, error) {
	// Fast path only acquires a read lock to retrieve storage if it already exists.
	d.mtx.RLock()
	store, found := d.storage[target]
	d.mtx.RUnlock()
	if found {
		return store, nil
	}

	d.mtx.Lock()
	defer d.mtx.Unlock()
	store, found = d.storage[target]
	if found {
		// Exit fast if the storage has been created since we last checked.
		return store, nil
	}

	// We know that storage doesn't exist yet, and have a lock so we know no other
	// threads will attempt to create it.
	store = inmem.New()
	d.storage[target] = store

	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	path := inventoryPath(nil)

	err = storage.MakeDir(ctx, store, txn, path)
	if err != nil {
		store.Abort(ctx, txn)
		return nil, fmt.Errorf("%v: unable to make directory for target %q %v",
			clienterrors.ErrWrite, target, err)
	}

	err = store.Commit(ctx, txn)
	if err != nil {
		// inmem.Store automatically aborts the transaction for us.
		return nil, fmt.Errorf("%v: unable to make directory for target %q %v",
			clienterrors.ErrWrite, target, err)
	}

	return store, nil
}
