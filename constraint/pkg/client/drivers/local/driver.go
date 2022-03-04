package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
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

	// storage is the Rego data store for Constraints and objects used in
	// referential Constraints.
	// storage internally uses mutexes to guard reads and writes during
	// transactions and queries, so we don't need to explicitly guard this with
	// a Mutex.
	storage storage.Store

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
func (d *Driver) AddTemplate(templ *templates.ConstraintTemplate) error {
	return d.compilers.addTemplate(templ, d.printEnabled)
}

// RemoveTemplate removes all Compilers and Constraints for templ.
// Returns nil if templ does not exist.
func (d *Driver) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) error {
	kind := templ.Spec.CRD.Spec.Names.Kind

	d.compilers.removeTemplate(kind)

	constraintParent := storage.Path{"constraint", kind}
	return d.RemoveData(ctx, constraintParent)
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
	return d.AddData(ctx, key.StoragePath(), params)
}

// RemoveConstraint removes Constraint from Rego storage. Future calls to Query
// will not be evaluated against the constraint. Queries which specify the
// constraint's key will silently not evaluate the Constraint.
func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	key := drivers.ConstraintKeyFrom(constraint)
	return d.RemoveData(ctx, key.StoragePath())
}

// AddData adds data to Rego storage at path.
func (d *Driver) AddData(ctx context.Context, path storage.Path, data interface{}) error {
	if len(path) == 0 {
		// Sanity-check path.
		// This would overwrite "data", erasing all Constraints and stored objects.
		return fmt.Errorf("%w: path must contain at least one path element: %+v", clienterrors.ErrPathInvalid, path)
	}

	// Initiate a new transaction. Since this is a write-transaction, it blocks
	// all other reads and writes, which includes running queries. If a transaction
	// is successfully created, all code paths must either Abort or Commit the
	// transaction to unblock queries and other writes.
	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	// We can't write to a location if its parent doesn't exist.
	// Thus, we check to see if anything already exists at the path.
	_, err = d.storage.Read(ctx, txn, path)
	if storage.IsNotFound(err) {
		// Insert an empty object at the path's parent so its parents are
		// recursively created.
		parent := path[:len(path)-1]
		err = storage.MakeDir(ctx, d.storage, txn, parent)
		if err != nil {
			d.storage.Abort(ctx, txn)
			return fmt.Errorf("%w: unable to make directory: %v", clienterrors.ErrWrite, err)
		}
	} else if err != nil {
		// We weren't able to read from storage - something serious is likely wrong.
		d.storage.Abort(ctx, txn)
		return fmt.Errorf("%w: %v", clienterrors.ErrRead, err)
	}

	err = d.storage.Write(ctx, txn, storage.AddOp, path, data)
	if err != nil {
		d.storage.Abort(ctx, txn)
		return fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	err = d.storage.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	return nil
}

// RemoveData deletes data from OPA.
func (d *Driver) RemoveData(ctx context.Context, key storage.Path) error {
	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	err = d.storage.Write(ctx, txn, storage.RemoveOp, key, interface{}(nil))
	if err != nil {
		d.storage.Abort(ctx, txn)
		if storage.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("%w: unable to remove data: %v", clienterrors.ErrWrite, err)
	}

	err = d.storage.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	return nil
}

// eval runs a query against compiler.
// path is the path to evaluate.
// input is the already-parsed Rego Value to use as input.
// Returns the Rego results, the trace if requested, or an error if there was
// a problem executing the query.
func (d *Driver) eval(ctx context.Context, compiler *ast.Compiler, path []string, input ast.Value, opts ...drivers.QueryOpt) (rego.ResultSet, *string, error) {
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

	args := []func(*rego.Rego){
		rego.Compiler(compiler),
		rego.Store(d.storage),
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
		parsedInput, err := toParsedInput(kindConstraints, reviewMap)
		if err != nil {
			return nil, nil, err
		}

		resultSet, trace, err := d.eval(ctx, compiler, path, parsedInput, opts...)
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
			rs, _, err := d.eval(ctx, compiler, []string{"data"}, nil)
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

// createTemplatePath returns the package path for a given template: templates[<name>].
func createTemplatePath(name string) string {
	return fmt.Sprintf(`templates[%q]`, name)
}

// parseModule parses the module and also fails empty modules.
func parseModule(path, rego string) (*ast.Module, error) {
	module, err := ast.ParseModule(path, rego)
	if err != nil {
		return nil, err
	}

	if module == nil {
		return nil, fmt.Errorf("%w: module %q is empty",
			clienterrors.ErrInvalidModule, path)
	}

	return module, nil
}

// rewriteModulePackage rewrites the module's package path to path.
func rewriteModulePackage(path string, module *ast.Module) error {
	pathParts, err := ast.ParseRef(path)
	if err != nil {
		return err
	}

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

func toParsedInput(constraints []*unstructured.Unstructured, review map[string]interface{}) (ast.Value, error) {
	// Store constraint keys in a format InterfaceToValue does not need to
	// round-trip through JSON.
	constraintKeys := toKeySlice(constraints)

	input := map[string]interface{}{
		"constraints": constraintKeys,
		"review":      review,
	}

	// Parse input into an ast.Value to avoid round-tripping through JSON when
	// possible.
	return ast.InterfaceToValue(input)
}
