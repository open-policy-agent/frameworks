package local

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	addModule     = "addModule"
	putModules    = "putModules"
	deleteModules = "deleteModules"
	addData       = "addData"
	deleteData    = "deleteData"
)

// testCase is a legacy test case type that performs a single call on the
// driver.
type testCase struct {
	Name          string
	Rules         rules
	Data          []data
	ErrorExpected bool
	ExpectedVals  []string
}

// rule corresponds to a rego snippet from the constraint template or other.
type rule struct {
	Path    string
	Content string
}

// rules is a list of rules.
type rules []rule

func (r rules) srcs() []string {
	var srcs []string
	for _, rule := range r {
		srcs = append(srcs, rule.Content)
	}
	return srcs
}

type data map[string]interface{}

// compositeTestCase is a testcase that consists of one or more API calls.
type compositeTestCase struct {
	Name      string
	Actions   []*action
	driverArg []Arg
}

// action corresponds to a method call for compositeTestCase.
type action struct {
	Op              string
	RuleNamePrefix  string // Used in PutModules/DeleteModules
	EvalPath        string // Path to evaluate
	Rules           rules
	Data            []data
	ErrorExpected   bool
	ExpectedBool    bool // Checks against DeleteModule returned bool
	WantDeleteCount int  // Checks against DeleteModules returned count
	ExpectedVals    []string
}

func (tt *compositeTestCase) run(t *testing.T) {
	d, err := New(tt.driverArg...)
	if err != nil {
		t.Fatal(err)
	}

	for idx, a := range tt.Actions {
		t.Run(fmt.Sprintf("action idx %d", idx), func(t *testing.T) {
			ctx := context.Background()

			switch a.Op {
			case addModule:
				for _, r := range a.Rules {
					err := d.PutModule(r.Path, r.Content)
					if (err == nil) && a.ErrorExpected {
						t.Fatalf("PUT err = nil; want non-nil")
					}
					if (err != nil) && !a.ErrorExpected {
						t.Fatalf("PUT err = \"%s\"; want nil", err)
					}
				}

			case putModules:
				err := d.putModules(a.RuleNamePrefix, a.Rules.srcs())
				if (err == nil) && a.ErrorExpected {
					t.Fatalf("PutModules err = nil; want non-nil")
				}
				if (err != nil) && !a.ErrorExpected {
					t.Fatalf("PutModules err = \"%s\"; want nil", err)
				}

			case deleteModules:
				count, err := d.deleteModules(a.RuleNamePrefix)
				if (err == nil) && a.ErrorExpected {
					t.Fatalf("DeleteModules err = nil; want non-nil")
				}
				if (err != nil) && !a.ErrorExpected {
					t.Fatalf("DeleteModules err = \"%s\"; want nil", err)
				}
				if count != a.WantDeleteCount {
					t.Fatalf("DeleteModules(\"%s\") = %d; want %d", a.RuleNamePrefix, count, a.WantDeleteCount)
				}

			default:
				t.Fatalf("unsupported op: %s", a.Op)
			}

			evalPath := "data.hello.r[a]"
			if a.EvalPath != "" {
				evalPath = a.EvalPath
			}

			res, _, err := d.eval(ctx, evalPath, nil, &drivers.QueryCfg{})
			if err != nil {
				t.Errorf("Eval error: %s", err)
			}
			if !resultsEqual(res, a.ExpectedVals, t) {
				fmt.Printf("For Test TestPutModule/%s: modules: %v\n", tt.Name, d.modules)
			}
		})
	}
}

func resultsEqual(res rego.ResultSet, exp []string, t *testing.T) bool {
	var ev []string
	for _, r := range res {
		i, ok := r.Bindings["a"].(string)
		if !ok {
			t.Fatalf("Unexpected result format: %v", r.Bindings)
		}
		ev = append(ev, i)
	}
	if len(ev) == 0 && len(exp) == 0 {
		return true
	}
	sort.Strings(ev)
	sort.Strings(exp)
	if !reflect.DeepEqual(ev, exp) {
		t.Errorf("Wanted results %v, got %v", exp, ev)
		return false
	}
	return true
}

func TestModules(t *testing.T) {
	providerCache := externaldata.NewCache()
	tc := []compositeTestCase{
		{
			Name: "PutModules then DeleteModules",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "m"}`},
					},
					ExpectedVals: []string{"m"},
				},
				{
					Op:              deleteModules,
					RuleNamePrefix:  "test1",
					WantDeleteCount: 3,
				},
			},
		},
		{
			Name: "PutModules with invalid empty string name",
			Actions: []*action{
				{
					Op: putModules,
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] {a = "m"}`},
					},
					ErrorExpected: true,
				},
			},
		},
		{
			Name: "PutModules with invalid sequence",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1_idx_",
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] {a = "m"}`},
					},
					ErrorExpected: true,
				},
			},
		},
		{
			Name: "PutModule with invalid prefix",
			Actions: []*action{
				{
					Op:            addModule,
					Rules:         rules{{"__modset_test1", `package hello r[a] {a = "m"}`}},
					ErrorExpected: true,
				},
			},
		},
		{
			Name: "PutModules twice, decrease src count",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "m"}`},
					},
					ExpectedVals: []string{"m"},
				},
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "a"}`},
					},
					ExpectedVals: []string{"a"},
				},
			},
		},
		{
			Name: "PutModules twice, increase src count",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "a"}`},
					},
					ExpectedVals: []string{"a"},
				},
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "m"}`},
					},
					ExpectedVals: []string{"m"},
				},
			},
		},
		{
			Name: "DeleteModules twice",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello r[a] { data.world.r[a] }`},
						{Content: `package world r[a] { data.foobar.r[a] }`},
						{Content: `package foobar r[a] {a = "m"}`},
					},
					ExpectedVals: []string{"m"},
				},
				{
					Op:              deleteModules,
					RuleNamePrefix:  "test1",
					WantDeleteCount: 3,
				},
				{
					Op:              deleteModules,
					RuleNamePrefix:  "test1",
					WantDeleteCount: 0,
				},
			},
		},
		{
			Name: "PutModule with valid builtin",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello  a = http.send({"method": "get", "url": "https://github.com/"})`},
					},
					ErrorExpected: false,
				},
			},
		},
		{
			Name: "PutModule with invalid builtin",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello  a = http.send({"method": "get", "url": "https://github.com/"})`},
					},
					ErrorExpected: true,
				},
			},
			driverArg: []Arg{DisableBuiltins("http.send")},
		},
		{
			Name: "PutModule with external data cache",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello  a = external_data({"provider": "my-provider", "keys": ["foo", 123]})`},
					},
					ErrorExpected: false,
				},
			},
			driverArg: []Arg{AddExternalDataProviderCache(providerCache)},
		},
		{
			Name: "PutModule with external data disabled",
			Actions: []*action{
				{
					Op:             putModules,
					RuleNamePrefix: "test1",
					Rules: rules{
						{Content: `package hello  a = external_data({"provider": "my-provider", "keys": ["foo", 123]})`},
					},
					ErrorExpected: true,
				},
			},
			driverArg: []Arg{DisableBuiltins("external_data")},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, tt.run)
	}
}

func TestPutModule(t *testing.T) {
	tc := []testCase{
		{
			Name:          "Put One Rule",
			Rules:         rules{{"test", `package hello r[a] {a = "1"}`}},
			ErrorExpected: false,
			ExpectedVals:  []string{"1"},
		},
		{
			Name:          "Put Duplicate Rules",
			Rules:         rules{{"test", `package hello r[a] {a = "q"}`}, {"test", `package hello r[a] {a = "v"}`}},
			ErrorExpected: false,
			ExpectedVals:  []string{"v"},
		},
		{
			Name:          "Put Multiple Rules",
			Rules:         rules{{"test", `package hello r[a] {a = "b"}`}, {"test2", `package hello r[a] {a = "v"}`}},
			ErrorExpected: false,
			ExpectedVals:  []string{"b", "v"},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()

			d, err := New()
			if err != nil {
				t.Fatal(err)
			}

			for _, r := range tt.Rules {
				err := d.PutModule(r.Path, r.Content)
				if (err == nil) && tt.ErrorExpected {
					t.Fatalf("err = nil; want non-nil")
				}
				if (err != nil) && !tt.ErrorExpected {
					t.Fatalf("err = \"%s\"; want nil", err)
				}
			}
			res, _, err := d.eval(ctx, "data.hello.r[a]", nil, &drivers.QueryCfg{})
			if err != nil {
				t.Errorf("Eval error: %s", err)
			}
			if !resultsEqual(res, tt.ExpectedVals, t) {
				fmt.Printf("For Test TestPutModule/%s: modules: %v\n", tt.Name, d.modules)
			}
		})
	}
}

func makeDataPath(s string) string {
	s = strings.ReplaceAll(s, "/", ".")
	return "data." + s[1:]
}

func TestPutData(t *testing.T) {
	tc := []testCase{
		{
			Name:          "Put One Datum",
			Data:          []data{{"/key": "my_value"}},
			ErrorExpected: false,
		},
		{
			Name:          "Overwrite Data",
			Data:          []data{{"/key": "my_value"}, {"/key": "new_value"}},
			ErrorExpected: false,
		},
		{
			Name:          "Multiple Data",
			Data:          []data{{"/key": "my_value", "/other_key": "new_value"}},
			ErrorExpected: false,
		},
		{
			Name:          "Add Some Depth",
			Data:          []data{{"/key/is/really/deep": "my_value"}},
			ErrorExpected: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()

			d, err := New()
			if err != nil {
				t.Fatal(err)
			}

			for _, data := range tt.Data {
				for k, v := range data {
					err := d.PutData(ctx, k, v)
					if (err == nil) && tt.ErrorExpected {
						t.Fatalf("err = nil; want non-nil")
					}
					if (err != nil) && !tt.ErrorExpected {
						t.Fatalf("err = \"%s\"; want nil", err)
					}
					res, _, err := d.eval(ctx, makeDataPath(k), nil, &drivers.QueryCfg{})
					if err != nil {
						t.Errorf("Eval error: %s", err)
					}
					if len(res) == 0 || len(res[0].Expressions) == 0 {
						t.Fatalf("No results: %v", res)
					}
					if !reflect.DeepEqual(res[0].Expressions[0].Value, v) {
						t.Errorf("%v != %v", v, res[0].Expressions[0].Value)
					}
				}
			}
		})
	}
}

func TestDeleteData(t *testing.T) {
	tc := []compositeTestCase{
		{
			Name: "Delete One Datum",
			Actions: []*action{
				{
					Op:            addData,
					Data:          []data{{"/key": "my_value"}},
					ErrorExpected: false,
					ExpectedVals:  []string{"m"},
				},
				{
					Op:            deleteData,
					Data:          []data{{"/key": "my_value"}},
					ErrorExpected: false,
					ExpectedBool:  true,
				},
			},
		},
		{
			Name: "Delete Data Twice",
			Actions: []*action{
				{
					Op:            addData,
					Data:          []data{{"/key": "my_value"}},
					ErrorExpected: false,
					ExpectedVals:  []string{"m"},
				},
				{
					Op:            deleteData,
					Data:          []data{{"/key": "my_value"}},
					ErrorExpected: false,
					ExpectedBool:  true,
				},
				{
					Op:            deleteData,
					Data:          []data{{"/key": "my_value"}},
					ErrorExpected: false,
					ExpectedBool:  false,
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()

			d, err := New()
			if err != nil {
				t.Fatal(err)
			}

			for _, a := range tt.Actions {
				for _, data := range a.Data {
					for k, v := range data {
						switch a.Op {
						case addData:
							err := d.PutData(ctx, k, v)
							if (err == nil) && a.ErrorExpected {
								t.Fatalf("PUT err = nil; want non-nil")
							}
							if (err != nil) && !a.ErrorExpected {
								t.Fatalf("PUT err = \"%s\"; want nil", err)
							}
							res, _, err := d.eval(ctx, makeDataPath(k), nil, &drivers.QueryCfg{})
							if err != nil {
								t.Errorf("Eval error: %s", err)
							}
							if len(res) == 0 || len(res[0].Expressions) == 0 {
								t.Fatalf("No results: %v", res)
							}
							if !reflect.DeepEqual(res[0].Expressions[0].Value, v) {
								t.Errorf("%v != %v", v, res[0].Expressions[0].Value)
							}
						case deleteData:
							b, err := d.DeleteData(ctx, k)
							if (err == nil) && a.ErrorExpected {
								t.Fatalf("DELETE err = nil; want non-nil")
							}
							if (err != nil) && !a.ErrorExpected {
								t.Fatalf("DELETE err = \"%s\"; want nil", err)
							}
							if b != a.ExpectedBool {
								t.Fatalf("DeleteData(\"%s\") = %t; want %t", k, b, a.ExpectedBool)
							}
							res, _, err := d.eval(ctx, makeDataPath(k), nil, &drivers.QueryCfg{})
							if err != nil {
								t.Errorf("Eval error: %s", err)
							}
							if len(res) != 0 {
								t.Fatalf("Got results after delete: %v", res)
							}
						default:
							t.Fatalf("unsupported op: %s", a.Op)
						}
					}
				}
			}
		})
	}
}

const queryModule = `
package hooks

violation[r] {
  review := object.get(input, "review", {})
  constraint := object.get(input, "constraint", {})
  r := {
    "constraint": constraint,
    "msg": "totally invalid",
    "metadata": {"details": {"not": "good"}},
    "review": review,
  }
}
`

func TestQuery(t *testing.T) {
	constraint := cts.MakeConstraint(t, "RequiredLabels", "require-a-label")
	err := unstructured.SetNestedField(constraint.Object, "world", "spec", "parameters", "hello")
	if err != nil {
		t.Fatal(err)
	}

	wantResults := []*types.Result{{
		Msg:        "totally invalid",
		Metadata:   map[string]interface{}{"details": map[string]interface{}{"not": "good"}},
		Constraint: constraint.DeepCopy(),
		Resource:   &handlertest.Review{Object: handlertest.Object{Name: "hi", Namespace: "there"}},
		Review: map[string]interface{}{
			"object": map[string]interface{}{"data": "", "name": "hi", "namespace": "there"},
		},
	}}

	ctx := context.Background()

	d, err := New()
	if err != nil {
		t.Fatal(err)
	}

	if err := d.PutModule("test", queryModule); err != nil {
		t.Fatal(err)
	}

	review := &handlertest.Review{Object: handlertest.Object{Name: "hi", Namespace: "there"}}

	res, _, err := d.Query(ctx, "target", constraint, review)
	if err != nil {
		t.Fatal(err)
	}

	results, err := ToResults(&handlertest.Handler{}, res)
	if err != nil {
		t.Fatal(err)
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Msg < results[j].Msg
	})
	sort.SliceStable(wantResults, func(i, j int) bool {
		return wantResults[i].Msg < wantResults[j].Msg
	})

	if diff := cmp.Diff(wantResults, results); diff != "" {
		t.Fatal(diff)
	}
}
