package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/regolib"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/regorewriter"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/print"
	opatypes "github.com/open-policy-agent/opa/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

const (
	libRoot   = "data.lib"
	violation = "violation"
)

func New(args ...Arg) (*Driver, error) {
	d := &Driver{}
	for _, arg := range args {
		err := arg(d)
		if err != nil {
			return nil, err
		}
	}

	err := Defaults()(d)
	if err != nil {
		return nil, err
	}

	if d.providerCache != nil {
		rego.RegisterBuiltin1(
			&rego.Function{
				Name:    "external_data",
				Decl:    opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A),
				Memoize: true,
			},
			externalDataBuiltin(d),
		)
	}

	return d, nil
}

var _ drivers.Driver = &Driver{}

type Driver struct {
	mtx sync.RWMutex

	// compilers is a map from target name to a map from Template Kind to the
	// compiler for that Template.
	compilers map[string]map[string]*ast.Compiler

	storage       storage.Store
	capabilities  *ast.Capabilities
	traceEnabled  bool
	printEnabled  bool
	printHook     print.Hook
	providerCache *externaldata.ProviderCache
	externs       []string
}

func (d *Driver) PutData(ctx context.Context, key handler.Key, data interface{}) error {
	if len(key) == 0 {
		return fmt.Errorf("%w: path must contain at least one path element: %q", clienterrors.ErrPathInvalid, []string(key))
	}

	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	_, err = d.storage.Read(ctx, txn, []string(key))
	if err != nil {
		if !storage.IsNotFound(err) {
			d.storage.Abort(ctx, txn)
			return fmt.Errorf("%w: %v", clienterrors.ErrRead, err)
		}

		parent := key[:len(key)-1]

		err = storage.MakeDir(ctx, d.storage, txn, []string(parent))
		if err != nil {
			return fmt.Errorf("%w: unable to make directory: %v", clienterrors.ErrWrite, err)
		}
	}

	if err = d.storage.Write(ctx, txn, storage.AddOp, []string(key), data); err != nil {
		d.storage.Abort(ctx, txn)
		return fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	err = d.storage.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}
	return nil
}

// DeleteData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors.
func (d *Driver) DeleteData(ctx context.Context, key handler.Key) (bool, error) {
	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return false, fmt.Errorf("%w: %v", clienterrors.ErrTransaction, err)
	}

	if err = d.storage.Write(ctx, txn, storage.RemoveOp, []string(key), interface{}(nil)); err != nil {
		d.storage.Abort(ctx, txn)
		if storage.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: unable to write data: %v", clienterrors.ErrWrite, err)
	}

	if err = d.storage.Commit(ctx, txn); err != nil {
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

func (d *Driver) Query(ctx context.Context, target string, constraint *unstructured.Unstructured, key handler.Key, review interface{}, opts ...drivers.QueryOpt) (rego.ResultSet, *string, error) {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	if len(d.compilers) == 0 {
		return nil, nil, nil
	}

	targetCompilers := d.compilers[target]
	if len(targetCompilers) == 0 {
		return nil, nil, nil
	}

	compiler := targetCompilers[constraint.GetKind()]
	if compiler == nil {
		return nil, nil, nil
	}

	input := map[string]interface{}{
		"constraint": constraint.Object,
	}

	if review != nil {
		input["review"] = review
	}

	path := []string{"hooks", "violation[result]"}

	return d.eval(ctx, compiler, path, input, opts...)
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	dt := make(map[string]map[string]rego.ResultSet)

	for targetName, targetCompilers := range d.compilers {
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

func (d *Driver) normalizeModulePaths(kind string, target templates.Target) (string, []string, error) {
	entryPrefix := createTemplatePath(kind)
	entryModule, err := parseModule(entryPrefix, target.Rego)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	if entryModule == nil {
		return "", nil, fmt.Errorf("%w: failed to parse module for unknown reason",
			clienterrors.ErrInvalidConstraintTemplate)
	}

	req := map[string]struct{}{violation: {}}

	if err = requireModuleRules(entryModule, req); err != nil {
		return "", nil, fmt.Errorf("%w: invalid rego: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}

	if err = rewriteModulePackage(entryPrefix, entryModule); err != nil {
		return "", nil, err
	}

	libPrefix := templateLibPrefix(kind)
	rr, err := regorewriter.New(
		regorewriter.NewPackagePrefixer(libPrefix),
		[]string{libRoot},
		d.externs)
	if err != nil {
		return "", nil, fmt.Errorf("creating rego rewriter: %w", err)
	}

	rr.AddEntryPointModule(entryPrefix, entryModule)
	for idx, src := range target.Libs {
		libPath := fmt.Sprintf(`%s["lib_%d"]`, libPrefix, idx)
		if err = rr.AddLib(libPath, src); err != nil {
			return "", nil, fmt.Errorf("%w: %v",
				clienterrors.ErrInvalidConstraintTemplate, err)
		}
	}

	sources, err := rr.Rewrite()
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}

	var mods []string
	err = sources.ForEachModule(func(m *regorewriter.Module) error {
		content, err2 := m.Content()
		if err2 != nil {
			return err2
		}
		mods = append(mods, string(content))
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}
	return entryPrefix, mods, nil
}

// ValidateConstraintTemplate validates the rego in template target by parsing
// rego modules.
func (d *Driver) ValidateConstraintTemplate(templ *templates.ConstraintTemplate) (string, []string, error) {
	if err := validateTargets(templ); err != nil {
		return "", nil, err
	}
	kind := templ.Spec.CRD.Spec.Names.Kind
	pkgPrefix := templateLibPrefix(kind)

	rr, err := regorewriter.New(
		regorewriter.NewPackagePrefixer(pkgPrefix),
		[]string{libRoot},
		d.externs)
	if err != nil {
		return "", nil, fmt.Errorf("creating rego rewriter: %w", err)
	}

	namePrefix := createTemplatePath(kind)
	entryPoint, err := parseModule(namePrefix, templ.Spec.Targets[0].Rego)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", clienterrors.ErrInvalidConstraintTemplate, err)
	}

	if entryPoint == nil {
		return "", nil, fmt.Errorf("%w: failed to parse module for unknown reason",
			clienterrors.ErrInvalidConstraintTemplate)
	}

	if err = rewriteModulePackage(namePrefix, entryPoint); err != nil {
		return "", nil, err
	}

	req := map[string]struct{}{violation: {}}

	if err = requireModuleRules(entryPoint, req); err != nil {
		return "", nil, fmt.Errorf("%w: invalid rego: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}

	targetSpec := templ.Spec.Targets[0]
	rr.AddEntryPointModule(namePrefix, entryPoint)
	for idx, libSrc := range targetSpec.Libs {
		libPath := fmt.Sprintf(`%s["lib_%d"]`, pkgPrefix, idx)
		if err = rr.AddLib(libPath, libSrc); err != nil {
			return "", nil, fmt.Errorf("%w: %v",
				clienterrors.ErrInvalidConstraintTemplate, err)
		}
	}

	sources, err := rr.Rewrite()
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}

	var mods []string
	err = sources.ForEachModule(func(m *regorewriter.Module) error {
		content, err2 := m.Content()
		if err2 != nil {
			return err2
		}
		mods = append(mods, string(content))
		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v",
			clienterrors.ErrInvalidConstraintTemplate, err)
	}
	return namePrefix, mods, nil
}

// AddTemplate implements drivers.Driver.
func (d *Driver) AddTemplate(templ *templates.ConstraintTemplate) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	err := d.compileTemplate(templ)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) compileTemplate(templ *templates.ConstraintTemplate) error {
	compilers := make(map[string]*ast.Compiler)

	kind := templ.Spec.CRD.Spec.Names.Kind
	for _, target := range templ.Spec.Targets {
		prefix, libs, err := d.normalizeModulePaths(kind, target)
		if err != nil {
			return err
		}

		compiler, err := d.compileTemplateTarget(prefix, target.Rego, libs)
		if err != nil {
			return err
		}

		compilers[target.Target] = compiler
	}

	for target, targetCompilers := range d.compilers {
		delete(targetCompilers, kind)
		d.compilers[target] = targetCompilers
	}

	if d.compilers == nil {
		d.compilers = make(map[string]map[string]*ast.Compiler)
	}

	for target, compiler := range compilers {
		targetCompilers := d.compilers[target]
		if targetCompilers == nil {
			targetCompilers = make(map[string]*ast.Compiler)
		}
		targetCompilers[kind] = compiler
		d.compilers[target] = targetCompilers
	}

	return nil
}

func (d *Driver) compileTemplateTarget(prefix string, rego string, libs []string) (*ast.Compiler, error) {
	compiler := ast.NewCompiler().
		WithCapabilities(d.capabilities).
		WithEnablePrintStatements(d.printEnabled)

	modules := make(map[string]*ast.Module)

	builtinModule, err := ast.ParseModule(regolib.TargetLibSrcPath, regolib.TargetLibSrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrParse, err)
	}
	modules[regolib.TargetLibSrcPath] = builtinModule

	path := prefix
	regoModule, err := ast.ParseModule(path, rego)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrParse, err)
	}
	modules[path] = regoModule

	for i, lib := range libs {
		libPath := fmt.Sprintf("%s%d", path, i)
		libModule, err := ast.ParseModule(libPath, lib)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", clienterrors.ErrParse, err)
		}
		modules[libPath] = libModule
	}

	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("%w: %v", clienterrors.ErrCompile, compiler.Errors)
	}

	return compiler, nil
}

// RemoveTemplate implements driver.Driver.
func (d *Driver) RemoveTemplate(templ *templates.ConstraintTemplate) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	for target, templateCompilers := range d.compilers {
		delete(templateCompilers, templ.Spec.CRD.Spec.Names.Kind)
		d.compilers[target] = templateCompilers
	}

	return nil
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

// validateTargets ensures that the targets field has the appropriate values.
func validateTargets(templ *templates.ConstraintTemplate) error {
	if templ == nil {
		return fmt.Errorf(`%w: ConstraintTemplate is nil`,
			clienterrors.ErrInvalidConstraintTemplate)
	}
	targets := templ.Spec.Targets
	if targets == nil {
		return fmt.Errorf(`%w: field "targets" not specified in ConstraintTemplate spec`,
			clienterrors.ErrInvalidConstraintTemplate)
	}

	switch len(targets) {
	case 0:
		return fmt.Errorf("%w: no targets specified: ConstraintTemplate must specify one target",
			clienterrors.ErrInvalidConstraintTemplate)
	case 1:
		return nil
	default:
		return fmt.Errorf("%w: multi-target templates are not currently supported",
			clienterrors.ErrInvalidConstraintTemplate)
	}
}
