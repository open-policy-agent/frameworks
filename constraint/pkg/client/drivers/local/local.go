package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	opatypes "github.com/open-policy-agent/opa/types"
	"k8s.io/utils/pointer"
)

const (
	moduleSetPrefix = "__modset_"
	moduleSetSep    = "_idx_"
)

type module struct {
	text   string
	parsed *ast.Module
}

type insertParam map[string]*module

func (i insertParam) add(name string, src string) error {
	m, err := ast.ParseModule(name, src)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrParse, name, err)
	}

	i[name] = &module{text: src, parsed: m}
	return nil
}

func New(args ...Arg) drivers.Driver {
	d := &driver{}
	for _, arg := range args {
		arg(d)
	}

	Defaults()(d)

	return d
}

var _ drivers.Driver = &driver{}

type driver struct {
	modulesMux    sync.RWMutex
	compilers     map[string]*ast.Compiler
	modules       map[string]*ast.Module
	storage       storage.Store
	capabilities  *ast.Capabilities
	traceEnabled  bool
	providerCache *externaldata.ProviderCache

	coreModules map[string]string
}

func (d *driver) Init(ctx context.Context) error {
	if d.providerCache == nil {
		return nil
	}

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:    "external_data",
			Decl:    opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A),
			Memoize: true,
		}, d.externalDataImpl,
	)

	return nil
}

// nolint: gocritic // rego.Builtin1 requires passing BuiltinContext, which is large.
func (d *driver) externalDataImpl(bctx rego.BuiltinContext, regorequest *ast.Term) (*ast.Term, error) {
	var regoReq externaldata.RegoRequest
	if err := ast.As(regorequest.Value, &regoReq); err != nil {
		return nil, err
	}
	// only primitive types are allowed for keys
	for _, key := range regoReq.Keys {
		switch v := key.(type) {
		case int:
		case int32:
		case int64:
		case string:
		case float64:
		case float32:
			break
		default:
			return externaldata.HandleError(http.StatusBadRequest, fmt.Errorf("type %v is not supported in external_data", v))
		}
	}

	provider, err := d.providerCache.Get(regoReq.ProviderName)
	if err != nil {
		return externaldata.HandleError(http.StatusBadRequest, err)
	}

	externaldataRequest := externaldata.NewProviderRequest(regoReq.Keys)
	reqBody, err := json.Marshal(externaldataRequest)
	if err != nil {
		return externaldata.HandleError(http.StatusInternalServerError, err)
	}

	req, err := http.NewRequest("POST", provider.Spec.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return externaldata.HandleError(http.StatusInternalServerError, err)
	}

	ctx, cancel := context.WithDeadline(bctx.Context, time.Now().Add(time.Duration(provider.Spec.Timeout)*time.Second))
	defer cancel()

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return externaldata.HandleError(http.StatusInternalServerError, err)
	}

	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return externaldata.HandleError(http.StatusInternalServerError, err)
	}

	var externaldataResponse externaldata.ProviderResponse
	if err := json.Unmarshal(respBody, &externaldataResponse); err != nil {
		return externaldata.HandleError(http.StatusInternalServerError, err)
	}

	regoResponse := externaldata.NewRegoResponse(resp.StatusCode, &externaldataResponse)
	return externaldata.PrepareRegoResponse(regoResponse)
}

func copyCompilers(compilers map[string]*ast.Compiler) map[string]*ast.Compiler {
	m := make(map[string]*ast.Compiler, len(compilers))
	for k, v := range compilers {
		m[k] = v
	}
	return m
}

func copyModules(modules map[string]*ast.Module) map[string]*ast.Module {
	m := make(map[string]*ast.Module, len(modules))
	for k, v := range modules {
		m[k] = v
	}
	return m
}

func (d *driver) checkModuleName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: module %q has no name",
			ErrModuleName, name)
	}

	if strings.HasPrefix(name, moduleSetPrefix) {
		return fmt.Errorf("%w: module %q has forbidden prefix %q",
			ErrModuleName, name, moduleSetPrefix)
	}

	return nil
}

func (d *driver) checkModuleSetName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: modules name prefix cannot be empty", ErrModulePrefix)
	}

	if strings.Contains(name, moduleSetSep) {
		return fmt.Errorf("%w: modules name prefix not allowed to contain the sequence %q", ErrModulePrefix, moduleSetSep)
	}

	return nil
}

func toModuleSetPrefix(prefix string) string {
	return fmt.Sprintf("%s%s%s", moduleSetPrefix, prefix, moduleSetSep)
}

func toModuleSetName(prefix string, idx int) string {
	return fmt.Sprintf("%s%d", toModuleSetPrefix(prefix), idx)
}

// PutModule implements drivers.Driver.
//
// PutModule is only ever used to add libraries which should be shared between
// the runtime environments of all ConstraintTemplates. It is only called on
// initialization.
func (d *driver) PutModule(ctx context.Context, name string, src string) error {
	if err := d.checkModuleName(name); err != nil {
		return err
	}

	insert := insertParam{}
	if err := insert.add(name, src); err != nil {
		return err
	}

	d.modulesMux.Lock()
	defer d.modulesMux.Unlock()

	if d.coreModules == nil {
		d.coreModules = make(map[string]string)
	}
	d.coreModules[name] = src

	// Kept for testing purposes, but unnecessary for sharded runtimes.
	_, err := d.alterModules(ctx, name, insert, nil)
	return err
}

// PutModules implements drivers.Driver.
//
// PutModules is only ever used to add a ConstraintTemplate to the Driver. We can
// be certain that when this is called, namePrefix corresponds to a unique OPA
// runtime environment. We delete the existing OPA environment, if one exists,
// and compile a new one.
func (d *driver) PutModules(ctx context.Context, namePrefix string, srcs []string) error {
	if err := d.checkModuleSetName(namePrefix); err != nil {
		return err
	}

	insert := insertParam{}

	for _, m := range d.coreModules {
		srcs = append(srcs, m)
	}

	for idx, src := range srcs {
		name := toModuleSetName(namePrefix, idx)
		if err := insert.add(name, src); err != nil {
			return err
		}
	}

	d.modulesMux.Lock()
	defer d.modulesMux.Unlock()

	var remove []string
	for _, name := range d.listModuleSet(namePrefix) {
		if _, found := insert[name]; !found {
			remove = append(remove, name)
		}
	}

	fmt.Printf("Adding %d Modules for %q\n", len(insert), namePrefix)

	_, err := d.alterModules(ctx, namePrefix, insert, remove)
	return err
}

// DeleteModule deletes a rule from OPA. Returns true if a rule was found and
// deleted, false if a rule was not found, and any errors.
func (d *driver) DeleteModule(ctx context.Context, name string) (bool, error) {
	if err := d.checkModuleName(name); err != nil {
		return false, err
	}

	d.modulesMux.Lock()
	defer d.modulesMux.Unlock()

	if _, found := d.modules[name]; !found {
		return false, nil
	}

	delete(d.coreModules, name)
	// Normally we would want to recompile all runtime environments here.
	// However, we don't hot-swap builtin libraries while Gatekeeper is running
	// so supporting that use case doesn't make sense.

	// Should be removed, just like the line in PutModule, as it serves no
	// purpose.
	count, err := d.alterModules(ctx, name, nil, []string{name})

	return count == 1, err
}

// alterModules alters the modules in the driver by inserting and removing
// the provided modules then returns the count of modules removed.
// alterModules expects that the caller is holding the modulesMux lock.
//
// environment is the name of the OPA runtime environment to modify.
func (d *driver) alterModules(ctx context.Context, environment string, insert insertParam, remove []string) (int, error) {
	updatedModules := copyModules(d.modules)
	for _, name := range remove {
		delete(updatedModules, name)
	}
	updatedCompilers := copyCompilers(d.compilers)
	delete(updatedCompilers, environment)

	for name, mod := range insert {
		updatedModules[name] = mod.parsed
	}

	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return 0, err
	}

	for _, name := range remove {
		if err := d.storage.DeletePolicy(ctx, txn, name); err != nil {
			d.storage.Abort(ctx, txn)
			return 0, err
		}
	}

	for name, mod := range insert {
		if err := d.storage.UpsertPolicy(ctx, txn, name, []byte(mod.text)); err != nil {
			d.storage.Abort(ctx, txn)
			return 0, err
		}
	}

	modules := make(map[string]*ast.Module)
	for name, m := range insert {
		modules[name] = m.parsed
	}

	c := ast.NewCompiler().WithPathConflictsCheck(storage.NonEmpty(ctx, d.storage, txn)).
		WithCapabilities(d.capabilities)

	if c.Compile(modules); c.Failed() {
		d.storage.Abort(ctx, txn)
		return 0, fmt.Errorf("%w: %v", ErrCompile, c.Errors)
	}

	updatedCompilers[environment] = c

	if err := d.storage.Commit(ctx, txn); err != nil {
		return 0, err
	}

	d.modules = updatedModules

	d.compilers = updatedCompilers

	return len(remove), nil
}

// DeleteModules implements drivers.Driver.
func (d *driver) DeleteModules(ctx context.Context, namePrefix string) (int, error) {
	if err := d.checkModuleSetName(namePrefix); err != nil {
		return 0, err
	}

	d.modulesMux.Lock()
	defer d.modulesMux.Unlock()

	return d.alterModules(ctx, namePrefix, nil, d.listModuleSet(namePrefix))
}

// listModuleSet returns the list of names corresponding to a given module
// prefix.
func (d *driver) listModuleSet(namePrefix string) []string {
	prefix := toModuleSetPrefix(namePrefix)

	var names []string
	for name := range d.modules {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}

	return names
}

func parsePath(path string) ([]string, error) {
	p, ok := storage.ParsePathEscaped(path)
	if !ok {
		return nil, fmt.Errorf("%w: path must begin with '/': %q", ErrPathInvalid, path)
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("%w: path must contain at least one path element: %q", ErrPathInvalid, path)
	}

	return p, nil
}

func (d *driver) PutData(ctx context.Context, path string, data interface{}) error {
	d.modulesMux.RLock()
	defer d.modulesMux.RUnlock()

	p, err := parsePath(path)
	if err != nil {
		return err
	}

	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransaction, err)
	}

	if _, err = d.storage.Read(ctx, txn, p); err != nil {
		if storage.IsNotFound(err) {
			if err = storage.MakeDir(ctx, d.storage, txn, p[:len(p)-1]); err != nil {
				return fmt.Errorf("%w: unable to make directory: %v", ErrWrite, err)
			}
		} else {
			d.storage.Abort(ctx, txn)
			return fmt.Errorf("%w: %v", ErrRead, err)
		}
	}

	if err = d.storage.Write(ctx, txn, storage.AddOp, p, data); err != nil {
		d.storage.Abort(ctx, txn)
		return fmt.Errorf("%w: unable to write data: %v", ErrWrite, err)
	}

	err = d.storage.Commit(ctx, txn)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransaction, err)
	}
	return nil
}

// DeleteData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors.
func (d *driver) DeleteData(ctx context.Context, path string) (bool, error) {
	d.modulesMux.RLock()
	defer d.modulesMux.RUnlock()

	p, err := parsePath(path)
	if err != nil {
		return false, err
	}

	txn, err := d.storage.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrTransaction, err)
	}

	if err = d.storage.Write(ctx, txn, storage.RemoveOp, p, interface{}(nil)); err != nil {
		d.storage.Abort(ctx, txn)
		if storage.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: unable to write data: %v", ErrWrite, err)
	}

	if err = d.storage.Commit(ctx, txn); err != nil {
		return false, fmt.Errorf("%w: %v", ErrTransaction, err)
	}

	return true, nil
}

func (d *driver) eval(ctx context.Context, path string, input interface{}, cfg *drivers.QueryCfg) (rego.ResultSet, *string, error) {
	d.modulesMux.RLock()
	defer d.modulesMux.RUnlock()

	var r2 rego.ResultSet

	var t *string

	for _, compiler := range d.compilers {
		args := []func(*rego.Rego){
			rego.Compiler(compiler),
			rego.Store(d.storage),
			rego.Input(input),
			rego.Query(path),
		}

		buf := topdown.NewBufferTracer()
		if d.traceEnabled || cfg.TracingEnabled {
			args = append(args, rego.QueryTracer(buf))
		}

		r := rego.New(args...)
		res, err := r.Eval(ctx)

		if d.traceEnabled || cfg.TracingEnabled {
			b := &bytes.Buffer{}
			topdown.PrettyTrace(b, *buf)
			t = pointer.StringPtr(b.String())
		}

		if err != nil {
			return nil, t, err
		}

		r2 = append(r2, res...)
	}

	return r2, t, nil
}

func (d *driver) Query(ctx context.Context, path string, input interface{}, opts ...drivers.QueryOpt) (*types.Response, error) {
	cfg := &drivers.QueryCfg{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Add a variable binding to the path.
	path = fmt.Sprintf("data.%s[result]", path)

	rs, trace, err := d.eval(ctx, path, input, cfg)
	if err != nil {
		return nil, err
	}

	var results []*types.Result
	for _, r := range rs {
		result := &types.Result{}
		b, err := json.Marshal(r.Bindings["result"])
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, result); err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	inp, err := json.MarshalIndent(input, "", "   ")
	if err != nil {
		return nil, err
	}

	return &types.Response{
		Trace:   trace,
		Results: results,
		Input:   pointer.StringPtr(string(inp)),
	}, nil
}

func (d *driver) Dump(ctx context.Context) (string, error) {
	d.modulesMux.RLock()
	defer d.modulesMux.RUnlock()

	mods := make(map[string]string, len(d.modules))
	for k, v := range d.modules {
		mods[k] = v.String()
	}

	data, _, err := d.eval(ctx, "data", nil, &drivers.QueryCfg{})
	if err != nil {
		return "", err
	}


	var dt []interface{}
	for _, da := range data {
		if len(da.Expressions) > 1 {
			return "", errors.New("too many expressions results")
		}

		for _, e := range da.Expressions {
			dt = append(dt, e.Value)
		}
	}

	resp := map[string]interface{}{
		"modules": mods,
		"data":    dt,
	}

	b, err := json.MarshalIndent(resp, "", "   ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
