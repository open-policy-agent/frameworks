package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
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

	// objectMtx ensures multiple queries for the same object are not running
	// simultaneously.
	objectMtx Sync

	// storage is the Rego data store for Constraints and objects used in
	// referential Constraints.
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
func (d *Driver) RemoveTemplate(ctx context.Context, templ *templates.ConstraintTemplate) error {
	kind := templ.Spec.CRD.Spec.Names.Kind

	d.compilers.removeTemplate(kind)

	constraintParent := handler.StoragePath{"constraint", kind}
	_, err := d.RemoveData(ctx, constraintParent)
	return err
}

// AddConstraint adds Constraint to Rego storage.
func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	params, _, err := unstructured.NestedFieldNoCopy(constraint.Object, "spec", "parameters")
	if err != nil {
		return err
	}

	// default .spec.parameters so that we don't need to default this in Rego.
	if params == nil {
		params = make(map[string]interface{})
	}

	key := drivers.ConstraintKeyFrom(constraint)
	return d.AddData(ctx, key.StoragePath(), params)
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	key := drivers.ConstraintKeyFrom(constraint)
	_, err := d.RemoveData(ctx, key.StoragePath())
	return err
}

func (d *Driver) AddData(ctx context.Context, key handler.StoragePath, data interface{}) error {
	if len(key) == 0 {
		return fmt.Errorf("%w: path must contain at least one path element: %q", clienterrors.ErrPathInvalid, []string(key))
	}

	path := []string(key)

	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	_, err = d.storage.Read(ctx, txn, path)
	if err != nil {
		if !storage.IsNotFound(err) {
			d.storage.Abort(ctx, txn)
			return fmt.Errorf("%w: %v", clienterrors.ErrRead, err)
		}

		parent := path[:len(path)-1]

		err = storage.MakeDir(ctx, d.storage, txn, parent)
		if err != nil {
			return fmt.Errorf("%w: unable to make directory: %v", clienterrors.ErrWrite, err)
		}
	}

	if err := d.storage.Write(ctx, txn, storage.AddOp, path, data); err != nil {
		d.storage.Abort(ctx, txn)
		return fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	err = d.storage.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}
	return nil
}

// RemoveData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors.
func (d *Driver) RemoveData(ctx context.Context, key handler.StoragePath) (bool, error) {
	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return false, fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	if err := d.storage.Write(ctx, txn, storage.RemoveOp, []string(key), interface{}(nil)); err != nil {
		d.storage.Abort(ctx, txn)
		if storage.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	if err := d.storage.Commit(ctx, txn); err != nil {
		return false, fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	return true, nil
}

func (d *Driver) eval(ctx context.Context, compiler *ast.Compiler, path []string, input interface{}, opts ...drivers.QueryOpt) (rego.ResultSet, *string, error) {
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
		rego.Input(input),
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

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, key handler.StoragePath, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {
	keyStr := key.String()
	tmpKey := []string{"tmp", keyStr}
	syncID := d.objectMtx.ID(tmpKey)
	d.objectMtx.Lock(syncID)

	defer func() {
		_, err := d.RemoveData(ctx, tmpKey)
		if err != nil {
			panic(err)
		}

		d.objectMtx.Unlock(syncID)
	}()

	err := d.AddData(ctx, tmpKey, review)
	if err != nil {
		return nil, nil, err
	}

	path := []string{"hooks", "violation[result]"}
	var results []*types.Result

	traceBuilder := strings.Builder{}

	kindConstraints := make(map[string][]*unstructured.Unstructured)
	for _, constraint := range constraints {
		kindConstraints[constraint.GetKind()] = append(kindConstraints[constraint.GetKind()], constraint)
	}

	constraintsMap := drivers.KeyMap(constraints)

	for kind, cs := range kindConstraints {
		compiler := d.compilers.getCompiler(target, kind)
		if compiler == nil {
			continue
		}

		var constraintKeys []drivers.ConstraintKey
		for _, constraint := range cs {
			constraintKeys = append(constraintKeys, drivers.ConstraintKeyFrom(constraint))
		}

		input := map[string]interface{}{
			"constraints": constraintKeys,
			"reviewKey":   keyStr,
		}

		resultSet, trace, err := d.eval(ctx, compiler, path, input, opts...)
		if err != nil {
			return nil, nil, err
		}
		if trace != nil {
			traceBuilder.WriteString(*trace)
		}

		for _, r := range resultSet {
			result, err := drivers.ToResult(constraintsMap, review, r)
			if err != nil {
				return nil, nil, err
			}
			results = append(results, result)
		}
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

// createTemplatePath returns the package path for a given template: templates.<target>.<name>.
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
