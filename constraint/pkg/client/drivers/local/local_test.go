package local

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/opa/rego"
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
					res, _, err := d.eval(ctx, nil, k, &drivers.QueryCfg{})
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
