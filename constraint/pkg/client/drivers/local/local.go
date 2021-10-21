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
	opatypes "github.com/open-policy-agent/opa/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/pointer"
)

const (
	moduleSetPrefix = "__modset_"
	moduleSetSep    = "_idx_"
)

type insertParam map[string]*ast.Module

func (i insertParam) add(name string, src string) error {
	m, err := ast.ParseModule(name, src)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrParse, name, err)
	}

	i[name] = m
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
	modulesMux sync.RWMutex

	compilers   map[string]*ast.Compiler
	constraints map[string][]*unstructured.Unstructured

	capabilities  *ast.Capabilities
	traceEnabled  bool
	providerCache *externaldata.ProviderCache
}

func (d *driver) Init(ctx context.Context) error {
	if d.providerCache != nil {
		rego.RegisterBuiltin1(
			&rego.Function{
				Name:    "external_data",
				Decl:    opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A),
				Memoize: true,
			},
			func(bctx rego.BuiltinContext, regorequest *ast.Term) (*ast.Term, error) {
				var regoReq externaldata.RegoRequest
				if err := ast.As(regorequest.Value, &regoReq); err != nil {
					return nil, err
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
			},
		)
	}
	return nil
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

func (d *driver) PutModule(ctx context.Context, name string, src string) error {
	return nil
}

// PutModules implements drivers.Driver.
func (d *driver) PutModules(ctx context.Context, kind string, srcs []string) error {
	insert := insertParam{}
	if len(srcs) != 1 {
		panic(len(srcs))
	}

	err := insert.add(fmt.Sprintf("templates[%q]", kind), srcs[0])
	if err != nil {
		return err
	}

	d.modulesMux.Lock()
	defer d.modulesMux.Unlock()

	_, err = d.alterModules(ctx, kind, insert, nil)
	return err
}

// DeleteModule deletes a rule from OPA. Returns true if a rule was found and deleted, false
// if a rule was not found, and any errors.
func (d *driver) DeleteModule(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// alterModules alters the modules in the driver by inserting and removing
// the provided modules then returns the count of modules removed.
// alterModules expects that the caller is holding the modulesMux lock.
func (d *driver) alterModules(_ context.Context, kind string, insert insertParam, _ []string) (int, error) {
	c := ast.NewCompiler().WithCapabilities(d.capabilities)

	if c.Compile(insert); c.Failed() {
		return 0, fmt.Errorf("%w: %v", ErrCompile, c.Errors)
	}

	d.compilers[kind] = c

	return 0, nil
}

// DeleteModules implements drivers.Driver.
func (d *driver) DeleteModules(ctx context.Context, namePrefix string) (int, error) {
	return 0, nil
}

// listModuleSet returns the list of names corresponding to a given module
// prefix.
func (d *driver) listModuleSet(namePrefix string) []string {
	return nil
}

func (d *driver) PutData(ctx context.Context, path string, data *unstructured.Unstructured) error {
	kind := strings.ToLower(data.GetKind())
	d.constraints[kind] = append(d.constraints[kind], data)
	return nil
}

// DeleteData deletes data from OPA and returns true if data was found and deleted, false
// if data was not found, and any errors.
func (d *driver) DeleteData(ctx context.Context, path string) (bool, error) {
	return false, nil
}

func (d *driver) eval(ctx context.Context, input interface{}, cfg *drivers.QueryCfg) (rego.ResultSet, *string, error) {
	d.modulesMux.RLock()
	defer d.modulesMux.RUnlock()

	// originally: hooks["%s"].violation
	// package templates[\"test.target\"].Foo\n\nviolation[{\"details\": {}, \"msg\": \"DENIED\"}]
	inputM, ok := input.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("got input type %T, want %T", input, map[string]interface{}{})
	}

	var results rego.ResultSet

	for kind, compiler := range d.compilers {
		path := fmt.Sprintf("data.%s.violation", kind)
		for _, constraint := range d.constraints[kind] {
			inputM["parameters"] = constraint.Object

			args := []func(*rego.Rego){
				rego.Compiler(compiler),
				rego.Input(inputM),
				rego.Query(path),
			}

			r := rego.New(args...)
			res, err := r.Eval(ctx)

			results = append(results, res...)

			if err != nil {
				return nil, nil, err
			}
		}
	}

	return results, nil, nil
}

func (d *driver) Query(ctx context.Context, input interface{}, opts ...drivers.QueryOpt) (*types.Response, error) {
	cfg := &drivers.QueryCfg{}
	for _, opt := range opts {
		opt(cfg)
	}

	rs, trace, err := d.eval(ctx, input, cfg)
	if err != nil {
		return nil, err
	}

	var results []*types.Result
	for _, r := range rs {
		for _, expr := range r.Expressions {
			values, ok := expr.Value.([]interface{})
			if !ok {
				return nil, fmt.Errorf("got expr.Value type %T, want %T", expr.Value, []string{})
			}

			for i, v := range values {
				vs, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("got expr.Value[%d] type %T, want %T", i, v, "")
				}
				results = append(results, &types.Result{
					Msg: vs,
				})
			}
		}
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

	data, _, err := d.eval(ctx, "data", &drivers.QueryCfg{})
	if err != nil {
		return "", err
	}

	var dt interface{}
	// There should be only 1 or 0 expression values
	if len(data) > 1 {
		return "", errors.New("too many dump results")
	}

	for _, da := range data {
		if len(data) > 1 {
			return "", errors.New("too many expressions results")
		}

		for _, e := range da.Expressions {
			dt = e.Value
		}
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
