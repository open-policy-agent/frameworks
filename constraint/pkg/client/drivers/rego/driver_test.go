package rego

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
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

type data struct {
	path  []string
	value string
}

func TestPutData(t *testing.T) {
	tc := []testCase{
		{
			Name: "Put One Datum",
			Data: []data{
				{path: []string{"key"}, value: "my_value"},
			},
			ErrorExpected: false,
		},
		{
			Name: "Overwrite Data",
			Data: []data{
				{path: []string{"key"}, value: "my_value"},
				{path: []string{"key"}, value: "new_value"},
			},
			ErrorExpected: false,
		},
		{
			Name: "Multiple Data",
			Data: []data{
				{path: []string{"key"}, value: "my_value"},
				{path: []string{"key2"}, value: "other_value"},
			},
			ErrorExpected: false,
		},
		{
			Name: "Add Some Depth",
			Data: []data{
				{path: []string{"key", "is", "really", "deep"}, value: "my_value"},
			},
			ErrorExpected: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()

			driver, err := New()
			if err != nil {
				t.Fatal(err)
			}

			compiler := ast.NewCompiler()
			compiler.Compile(nil)

			for _, d := range tt.Data {
				err := driver.AddData(ctx, "foo", d.path, d.value)
				if (err == nil) && tt.ErrorExpected {
					t.Fatalf("err = nil; want non-nil")
				}
				if (err != nil) && !tt.ErrorExpected {
					t.Fatalf("err = \"%s\"; want nil", err)
				}

				res, _, err := driver.eval(ctx, compiler, "foo", inventoryPath(d.path), nil)
				if err != nil {
					t.Fatalf("Eval error: %s", err)
				}
				if len(res) == 0 || len(res[0].Expressions) == 0 {
					t.Fatalf("No results: %v", res)
				}

				if diff := cmp.Diff(d.value, res[0].Expressions[0].Value); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}
