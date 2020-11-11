package client

import (
	"testing"
)

type regoTestCase struct {
	Name          string
	Rego          string
	Path          string
	ErrorExpected bool
	ExpectedRego  string
	ArityExpected int
	RequiredRules map[string]struct{}
}

func TestRequireRules(t *testing.T) {
	tc := []regoTestCase{
		{
			Name:          "No Required Rules",
			Rego:          `package hello`,
			ErrorExpected: false,
		},
		{
			Name:          "Bad Rego",
			Rego:          `package hello {dangling bracket`,
			ErrorExpected: true,
		},
		{
			Name:          "Required Rule",
			Rego:          `package hello r{1 == 1}`,
			RequiredRules: map[string]struct{}{"r": {}},
			ErrorExpected: false,
		},
		{
			Name:          "Required Rule Extras",
			Rego:          `package hello r[v]{v == 1} q{3 == 3}`,
			RequiredRules: map[string]struct{}{"r": {}},
			ErrorExpected: false,
		},
		{
			Name:          "Required Rule Multiple",
			Rego:          `package hello r[v]{v == 1} q{3 == 3}`,
			RequiredRules: map[string]struct{}{"r": {}, "q": {}},
			ErrorExpected: false,
		},
		{
			Name:          "Required Rule Missing",
			Rego:          `package hello`,
			RequiredRules: map[string]struct{}{"r": {}},
			ErrorExpected: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.Name, func(t *testing.T) {
			mod, err := parseModule("foo", tt.Rego)
			if err == nil {
				err = requireRulesModule(mod, tt.RequiredRules)
			}

			if (err == nil) && tt.ErrorExpected {
				t.Fatalf("err = nil; want non-nil")
			}
			if (err != nil) && !tt.ErrorExpected {
				t.Fatalf("err = \"%s\"; want nil", err)
			}
		})
	}
}
