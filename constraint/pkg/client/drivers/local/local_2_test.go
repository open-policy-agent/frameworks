package local

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/opa/ast"
)

const (
	Module string = `
package foobar

fooisbar[msg] {
  input.foo == "bar"
  msg := "input.foo is bar"
}
`

	UnparseableModule string = `
package foobar

fooisbar[msg] 
  input.foo == "bar"
  msg := "input.foo is bar"
}
`

	UncompilableModule string = `
package foobar

fooisbar[msg] {
  foo == "bar"
  msg := "input.foo is bar"
}
`
)

func TestDriver_PutModule(t *testing.T) {
	testCases := []struct {
		name       string
		beforeModules map[string]*ast.Module
		moduleName string
		moduleSrc  string

		wantErr     error
		wantModules []string
	}{
		{
			name:       "empty module name",
			moduleName: "",
			moduleSrc:  "",

			wantErr:     ErrModuleName,
			wantModules: nil,
		},
		{
			name:       "module set prefix",
			moduleName: moduleSetPrefix + "foo",
			moduleSrc:  "",

			wantErr:     ErrModuleName,
			wantModules: nil,
		},
		{
			name:       "module set suffix allowed",
			moduleName: "foo" + moduleSetPrefix,
			moduleSrc:  Module,

			wantErr:     nil,
			wantModules: []string{"foo" + moduleSetPrefix},
		},
		{
			name:       "valid module",
			moduleName: "foo",
			moduleSrc:  Module,

			wantErr:     nil,
			wantModules: []string{"foo"},
		},
		{
			name:       "unparseable module",
			moduleName: "foo",
			moduleSrc:  UnparseableModule,

			wantErr:     ErrParse,
			wantModules: nil,
		},
		{
			name:       "uncompilable module",
			moduleName: "foo",
			moduleSrc:  UncompilableModule,

			wantErr:     ErrCompile,
			wantModules: nil,
		},
		{
			name:       "replace module",
			beforeModules: map[string]*ast.Module{
				"foo": {},
			},
			moduleName: "foo",
			moduleSrc:  Module,

			wantErr:     nil,
			wantModules: []string{"foo"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New(ArgModules(tc.beforeModules))

			dr, ok := d.(*driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &driver{})
			}

			gotErr := d.PutModule(ctx, tc.moduleName, tc.moduleSrc)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got PutModule() error = %v, want %v", gotErr, tc.wantErr)
			}

			gotModules := make([]string, 0, len(dr.modules))
			for gotModule := range dr.modules {
				gotModules = append(gotModules, gotModule)
			}
			sort.Strings(gotModules)

			if diff := cmp.Diff(tc.wantModules, gotModules, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}
