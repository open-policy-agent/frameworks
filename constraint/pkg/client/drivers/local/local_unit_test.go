package local

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
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
	TemplateModule string = `
package something

violation[msg] {msg := "always"}`

	MockTemplate      string = "MockConstraintTemplate"
	MockTargetHandler string = "foo"
)

func TestDriver_PutModule(t *testing.T) {
	testCases := []struct {
		name          string
		beforeModules map[string]*ast.Module
		moduleName    string
		moduleSrc     string

		wantErr     error
		wantModules []string
	}{
		{
			name:       "empty module name",
			moduleName: "",
			moduleSrc:  Module,

			wantErr:     clienterrors.ErrModuleName,
			wantModules: nil,
		},
		{
			name:       "module set prefix",
			moduleName: moduleSetPrefix + "foo",
			moduleSrc:  "",

			wantErr:     clienterrors.ErrModuleName,
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

			wantErr:     clienterrors.ErrParse,
			wantModules: nil,
		},
		{
			name:       "uncompilable module",
			moduleName: "foo",
			moduleSrc:  UncompilableModule,

			wantErr:     clienterrors.ErrCompile,
			wantModules: nil,
		},
		{
			name: "replace module",
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
			d := New(Modules(tc.beforeModules))

			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &Driver{})
			}

			gotErr := d.PutModule(tc.moduleName, tc.moduleSrc)
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

func TestDriver_PutModules(t *testing.T) {
	testCases := []struct {
		name          string
		beforeModules map[string][]string

		prefix string
		srcs   []string

		wantErr     error
		wantModules []string
	}{
		{
			name:   "empty module prefix",
			prefix: "",
			srcs:   []string{},

			wantErr:     clienterrors.ErrModulePrefix,
			wantModules: nil,
		},
		{
			name:   "module prefix with separator",
			prefix: "a_idx_b",
			srcs:   []string{},

			wantErr:     clienterrors.ErrModulePrefix,
			wantModules: nil,
		},
		{
			name:   "no sources in module set",
			prefix: "foo",
			srcs:   []string{},

			wantErr:     nil,
			wantModules: nil,
		},
		{
			name:   "add one module",
			prefix: "foo",
			srcs:   []string{Module},

			wantErr:     nil,
			wantModules: []string{toModuleSetName("foo", 0)},
		},
		{
			name:   "add unparseable module",
			prefix: "foo",
			srcs:   []string{UnparseableModule},

			wantErr:     clienterrors.ErrParse,
			wantModules: nil,
		},
		{
			name:   "add uncompilable module",
			prefix: "foo",
			srcs:   []string{UncompilableModule},

			wantErr:     clienterrors.ErrCompile,
			wantModules: nil,
		},
		{
			name:   "add two modules",
			prefix: "foo",
			srcs:   []string{Module, Module},

			wantErr: nil,
			wantModules: []string{
				toModuleSetName("foo", 0),
				toModuleSetName("foo", 1),
			},
		},
		{
			name: "add to module set",
			beforeModules: map[string][]string{
				"foo": {Module},
			},
			prefix: "foo",
			srcs:   []string{Module, Module},

			wantErr: nil,
			wantModules: []string{
				toModuleSetName("foo", 0),
				toModuleSetName("foo", 1),
			},
		},
		{
			name: "remove from module set",
			beforeModules: map[string][]string{
				"foo": {Module, Module},
			},
			prefix: "foo",
			srcs:   []string{Module},

			wantErr: nil,
			wantModules: []string{
				toModuleSetName("foo", 0),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T", dr, &Driver{})
			}
			for prefix, src := range tc.beforeModules {
				err := dr.putModules(prefix, src)
				if err != nil {
					t.Fatal(err)
				}
			}

			gotErr := dr.putModules(tc.prefix, tc.srcs)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got PutModules() error = %v, want %v", gotErr, tc.wantErr)
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

func TestDriver_DeleteModules(t *testing.T) {
	testCases := []struct {
		name          string
		beforeModules map[string]int

		prefix string

		wantErr     error
		wantDeleted int
		wantModules []string
	}{
		{
			name: "empty module prefix",
			beforeModules: map[string]int{
				"foo": 1,
				"bar": 2,
			},

			prefix: "",

			wantErr:     clienterrors.ErrModulePrefix,
			wantDeleted: 0,
			wantModules: []string{
				toModuleSetName("bar", 0),
				toModuleSetName("bar", 1),
				toModuleSetName("foo", 0),
			},
		},
		{
			name: "delete one module",
			beforeModules: map[string]int{
				"foo": 1,
				"bar": 2,
			},

			prefix: "foo",

			wantErr:     nil,
			wantDeleted: 1,
			wantModules: []string{
				toModuleSetName("bar", 0),
				toModuleSetName("bar", 1),
			},
		},
		{
			name: "delete two modules",
			beforeModules: map[string]int{
				"foo": 1,
				"bar": 2,
			},

			prefix: "bar",

			wantErr:     nil,
			wantDeleted: 2,
			wantModules: []string{
				toModuleSetName("foo", 0),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &Driver{})
			}
			for prefix, count := range tc.beforeModules {
				modules := make([]string, count)
				for i := 0; i < count; i++ {
					modules[i] = Module
				}
				err := dr.putModules(prefix, modules)
				if err != nil {
					t.Fatal(err)
				}
			}

			gotDeleted, gotErr := dr.deleteModules(tc.prefix)
			if gotDeleted != tc.wantDeleted {
				t.Errorf("got DeleteModules() = %v, want %v", gotDeleted, tc.wantDeleted)
			}

			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got DeleteModules() error = %v, want %v", gotErr, tc.wantErr)
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

func TestDriver_AddTemplates(t *testing.T) {
	testCases := []struct {
		name          string
		rego          string
		targetHandler string
		externs       []string

		wantErr     error
		wantModules []string
	}{
		{
			name:        "no target",
			wantErr:     clienterrors.ErrInvalidConstraintTemplate,
			wantModules: nil,
		},
		{
			name:          "rego missing violation",
			targetHandler: MockTargetHandler,
			rego:          Module,
			wantErr:       clienterrors.ErrInvalidConstraintTemplate,
			wantModules:   nil,
		},
		{
			name:          "valid template",
			targetHandler: MockTargetHandler,
			rego: `
package something

violation[msg] {msg := "always"}`,
			wantModules: []string{toModuleSetName(createTemplatePath(MockTargetHandler, MockTemplate), 0)},
		},
		{
			name:          "inventory disallowed template",
			targetHandler: MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			wantErr: clienterrors.ErrInvalidConstraintTemplate,
		},
		{
			name:          "inventory allowed template",
			targetHandler: MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs:     []string{"data.inventory"},
			wantErr:     nil,
			wantModules: []string{toModuleSetName(createTemplatePath(MockTargetHandler, MockTemplate), 0)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T", dr, &Driver{})
			}
			dr.SetExterns(tc.externs)
			tmpl := CreateTemplate(tc.targetHandler, tc.rego)
			gotErr := dr.AddTemplate(tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
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

func TestDriver_RemoveTemplates(t *testing.T) {
	testCases := []struct {
		name          string
		rego          string
		targetHandler string
		externs       []string
		wantErr       error
	}{
		{
			name:          "valid template",
			targetHandler: MockTargetHandler,
			rego: `
package something

violation[msg] {msg := "always"}`,
		},
		{
			name:          "inventory allowed template",
			targetHandler: MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs: []string{"data.inventory"},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T", dr, &Driver{})
			}
			dr.SetExterns(tc.externs)
			tmpl := CreateTemplate(tc.targetHandler, tc.rego)
			gotErr := dr.AddTemplate(tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
			}
			if len(dr.modules) == 0 {
				t.Errorf("driver failed to add module")
			}
			gotErr = dr.RemoveTemplate(context.Background(), tmpl)
			if gotErr != nil {
				t.Errorf("err = %v; want nil", gotErr)
			}
			if len(dr.modules) != 0 {
				t.Errorf("driver has module = %v; want nil", len(dr.modules))
			}
		})
	}
}

func TestDriver_AddConstraint(t *testing.T) {
	testCases := []struct {
		name                   string
		template               *templates.ConstraintTemplate
		constraint             *unstructured.Unstructured
		wantAddConstraintError error
	}{
		{
			name:       "Good Constraint",
			template:   CreateTemplate(MockTargetHandler, TemplateModule),
			constraint: MakeConstraint(t, MockTemplate, "tc_good_constraint"),
		},
		{
			name:                   "No Name",
			template:               CreateTemplate(MockTargetHandler, TemplateModule),
			constraint:             MakeConstraint(t, MockTemplate, ""),
			wantAddConstraintError: ErrInvalidConstraint,
		},
		{
			name:                   "No Kind",
			template:               CreateTemplate(MockTargetHandler, TemplateModule),
			constraint:             MakeConstraint(t, "", "foo-constraint"),
			wantAddConstraintError: ErrMissingConstraintTemplate,
		},
		{
			name:                   "No Template",
			template:               CreateTemplate(MockTargetHandler, TemplateModule),
			constraint:             MakeConstraint(t, "TemplateMissing", "foo-constraint"),
			wantAddConstraintError: ErrMissingConstraintTemplate,
		},
		{
			name:     "No Group",
			template: CreateTemplate(MockTargetHandler, TemplateModule),
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": MockTemplate,
				},
			},
			wantAddConstraintError: ErrInvalidConstraint,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T", dr, &Driver{})
			}
			err := dr.AddTemplate(tc.template)
			if err != nil {
				t.Fatalf("got AddTemplate() error = %v", err)
			}
			err = dr.AddConstraint(context.Background(), tc.constraint)
			if !errors.Is(err, tc.wantAddConstraintError) {
				t.Fatalf("got AddConstraint() error = %v, want %v",
					err, tc.wantAddConstraintError)
			}
			if err == nil {
				storage, err := dr.Dump(context.Background())
				if err != nil {
					t.Fatalf("could not dump driver %v", err)
				}
				if !strings.Contains(storage, tc.constraint.GetName()) {
					t.Errorf("expected constraint %s not added to driver", tc.constraint.GetName())
				}
			}
		})
	}
}

func TestDriver_RemoveConstraint(t *testing.T) {
	tcs := []struct {
		name       string
		template   *templates.ConstraintTemplate
		constraint *unstructured.Unstructured
		toRemove   *unstructured.Unstructured
		wantError  error
	}{
		{
			name:       "Good Constraint",
			template:   CreateTemplate(MockTargetHandler, TemplateModule),
			constraint: MakeConstraint(t, MockTemplate, "foo"),
			toRemove:   MakeConstraint(t, MockTemplate, "foo"),
			wantError:  nil,
		},
		{
			name:       "No name",
			template:   CreateTemplate(MockTargetHandler, TemplateModule),
			constraint: MakeConstraint(t, MockTemplate, "foo"),
			toRemove:   MakeConstraint(t, MockTemplate, ""),
			wantError:  ErrInvalidConstraint,
		},
		{
			name:       "No Kind",
			template:   CreateTemplate(MockTargetHandler, TemplateModule),
			constraint: MakeConstraint(t, MockTemplate, "foo"),
			toRemove:   MakeConstraint(t, "", "foo"),
			wantError:  ErrMissingConstraintTemplate,
		},
		{
			name:      "No Template",
			toRemove:  MakeConstraint(t, "Foos", "foo"),
			wantError: ErrMissingConstraintTemplate,
		},
		{
			name:      "No Constraint",
			template:  CreateTemplate(MockTargetHandler, TemplateModule),
			toRemove:  MakeConstraint(t, MockTemplate, "foo"),
			wantError: nil,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New()
			dr, ok := d.(*Driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T", dr, &Driver{})
			}

			if tc.template != nil {
				err := dr.AddTemplate(tc.template)
				if err != nil {
					t.Fatal(err)
				}
			}

			if tc.constraint != nil {
				err := dr.AddConstraint(ctx, tc.constraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			err := dr.RemoveConstraint(context.Background(), tc.toRemove)

			if !errors.Is(err, tc.wantError) {
				t.Errorf("got RemoveConstraint error = %v, want %v",
					err, tc.wantError)
			}
		})
	}
}

func TestDriver_PutData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  string
		beforeValue interface{}
		path        string
		value       interface{}

		wantErr error
	}{
		{
			name:  "empty path",
			path:  "",
			value: map[string]string{},

			wantErr: clienterrors.ErrPathInvalid,
		},
		{
			name:  "root path",
			path:  "/",
			value: map[string]string{},

			wantErr: clienterrors.ErrPathInvalid,
		},
		{
			name:  "valid write",
			path:  "/foo",
			value: map[string]string{"foo": "bar"},

			wantErr: nil,
		},
		{
			name:        "valid overwrite",
			beforePath:  "/foo",
			beforeValue: map[string]string{"foo": "bar"},
			path:        "/foo",
			value:       map[string]string{"foo": "qux"},

			wantErr: nil,
		},
		{
			name:        "write to subdirectory of existing data",
			beforePath:  "/foo",
			beforeValue: map[string]string{"foo": "bar"},
			path:        "/foo/bar",
			value:       map[string]string{"foo": "qux"},

			wantErr: clienterrors.ErrWrite,
		},
		{
			name:        "write to subdirectory of non-object",
			beforePath:  "/foo",
			beforeValue: "bar",
			path:        "/foo/bar",
			value:       map[string]string{"foo": "qux"},

			wantErr: clienterrors.ErrWrite,
		},
		{
			name:        "write to parent directory of existing data",
			beforePath:  "/foo/bar",
			beforeValue: map[string]string{"foo": "bar"},
			path:        "/foo",
			value:       map[string]string{"foo": "qux"},

			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := &fakeStorage{}
			d := New(Storage(s))

			if tc.beforeValue != nil {
				err := d.PutData(ctx, tc.beforePath, tc.beforeValue)
				if err != nil {
					t.Fatalf("got setup PutData() error = %v, want %v", err, nil)
				}
			}

			err := d.PutData(ctx, tc.path, tc.value)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got PutData() error = %v, want %v",
					err, tc.wantErr)
			}

			if errors.Is(tc.wantErr, clienterrors.ErrPathInvalid) {
				return
			}

			// Verify the state of data in storage.

			readPath := tc.path
			wantValue := tc.value
			if tc.wantErr != nil {
				// We encountered an error writing data, so we expect the original data to be unchanged.
				readPath = tc.beforePath
				wantValue = tc.beforeValue
			}

			path, err := parsePath(readPath)
			if err != nil {
				t.Fatalf("got parsePath() e = %v, want %v", err, nil)
			}

			gotValue, err := s.Read(ctx, nil, path)
			if err != nil {
				t.Fatalf("got fakeStorage.Read() error = %v, want %v", err, nil)
			}

			if diff := cmp.Diff(wantValue, gotValue); diff != "" {
				t.Errorf("read data did not equal expected (-want, +got): %v", diff)
			}
		})
	}
}

func TestDriver_PutData_StorageErrors(t *testing.T) {
	testCases := []struct {
		name    string
		storage storage.Store

		wantErr error
	}{
		{
			name:    "success",
			storage: &fakeStorage{},
			wantErr: nil,
		},
		{
			name:    "transaction error",
			storage: &transactionErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
		{
			name:    "read error",
			storage: &readErrorStorage{},
			wantErr: clienterrors.ErrRead,
		},
		{
			name:    "write error",
			storage: &writeErrorStorage{},
			wantErr: clienterrors.ErrWrite,
		},
		{
			name:    "commit error",
			storage: &commitErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New(Storage(tc.storage))

			path := "/foo"
			value := map[string]string{"bar": "qux"}
			err := d.PutData(ctx, path, value)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got PutData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriver_DeleteData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  string
		beforeValue interface{}
		path        string

		wantDeleted bool
		wantErr     error
	}{
		{
			name:        "empty path",
			beforePath:  "/foo",
			beforeValue: "bar",
			path:        "",

			wantDeleted: false,
			wantErr:     clienterrors.ErrPathInvalid,
		},
		{
			name:        "success",
			beforePath:  "/foo",
			beforeValue: "bar",
			path:        "/foo",

			wantDeleted: true,
			wantErr:     nil,
		},
		{
			name:        "non existent",
			beforePath:  "/foo",
			beforeValue: "bar",
			path:        "/qux",

			wantDeleted: false,
			wantErr:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := &fakeStorage{}
			d := New(Storage(s))

			err := d.PutData(ctx, tc.beforePath, tc.beforeValue)
			if err != nil {
				t.Fatalf("got setup PutData() error = %v, want %v", err, nil)
			}

			deleted, err := d.DeleteData(ctx, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got DeleteData() error = %v, want %v", err, tc.wantErr)
			}
			if deleted != tc.wantDeleted {
				t.Fatalf("got DeleteData() = %t, want %t", deleted, tc.wantDeleted)
			}

			var wantValue interface{}
			if !tc.wantDeleted {
				wantValue = tc.beforeValue
			}

			if diff := cmp.Diff(wantValue, s.values[tc.beforePath]); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func TestDriver_DeleteData_StorageErrors(t *testing.T) {
	testCases := []struct {
		name    string
		storage storage.Store

		wantErr error
	}{
		{
			name:    "success",
			storage: &fakeStorage{},
			wantErr: nil,
		},
		{
			name:    "transaction error",
			storage: &transactionErrorStorage{},
			wantErr: clienterrors.ErrTransaction,
		},
		{
			name:    "write error",
			storage: &writeErrorStorage{},
			wantErr: clienterrors.ErrWrite,
		},
		{
			name: "commit error",
			storage: &commitErrorStorage{
				fakeStorage: fakeStorage{values: map[string]interface{}{
					"/foo": "bar",
				}},
			},
			wantErr: clienterrors.ErrTransaction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New(Storage(tc.storage))

			path := "/foo"
			_, err := d.DeleteData(ctx, path)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got DeleteData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

type fakeStorage struct {
	storage.Store

	policies map[string][]byte
	values   map[string]interface{}
}

var _ storage.Store = &fakeStorage{}

func (s *fakeStorage) UpsertPolicy(_ context.Context, _ storage.Transaction, name string, bytes []byte) error {
	if s.policies == nil {
		s.policies = make(map[string][]byte)
	}

	s.policies[name] = bytes

	return nil
}

func (s *fakeStorage) DeletePolicy(_ context.Context, _ storage.Transaction, name string) error {
	delete(s.policies, name)

	return nil
}

func (s *fakeStorage) NewTransaction(_ context.Context, _ ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, nil
}

func (s *fakeStorage) Read(_ context.Context, _ storage.Transaction, path storage.Path) (interface{}, error) {
	value, found := s.values[path.String()]
	if !found {
		return nil, &storage.Error{Code: storage.NotFoundErr}
	}

	return value, nil
}

func (s *fakeStorage) Write(_ context.Context, _ storage.Transaction, _ storage.PatchOp, path storage.Path, value interface{}) error {
	if s.values == nil {
		s.values = make(map[string]interface{})
	}

	if value == nil && s.values[path.String()] == nil {
		return &storage.Error{Code: storage.NotFoundErr}
	}

	s.values[path.String()] = value

	return nil
}

func (s *fakeStorage) Commit(_ context.Context, _ storage.Transaction) error {
	return nil
}

func (s *fakeStorage) Abort(_ context.Context, _ storage.Transaction) {}

type transactionErrorStorage struct {
	fakeStorage
}

func (s *transactionErrorStorage) NewTransaction(_ context.Context, _ ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, errors.New("error making new transaction")
}

type commitErrorStorage struct {
	fakeStorage
}

func (s *commitErrorStorage) Commit(_ context.Context, _ storage.Transaction) error {
	return errors.New("error committing changes")
}

type writeErrorStorage struct {
	fakeStorage
}

func (s *writeErrorStorage) Write(_ context.Context, _ storage.Transaction, _ storage.PatchOp, _ storage.Path, _ interface{}) error {
	return errors.New("error writing data")
}

type readErrorStorage struct {
	fakeStorage
}

func (s *readErrorStorage) Read(_ context.Context, _ storage.Transaction, _ storage.Path) (interface{}, error) {
	return nil, errors.New("error writing data")
}

// TODO: move the mocking functions to a pkg that can be shared with client.
func CreateTemplate(targetHandler, rego string) *templates.ConstraintTemplate {
	tmpl := &templates.ConstraintTemplate{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name: "mockconstrainttemplate",
		},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{
				Spec: templates.CRDSpec{
					Names: templates.Names{
						Kind:       MockTemplate,
						ShortNames: nil,
					},
				},
			},
		},
	}
	if targetHandler == "" && rego == "" {
		return tmpl
	}
	tmpl.Spec.Targets = []templates.Target{
		{
			Target: targetHandler,
			Rego:   rego,
		},
	}
	return tmpl
}

// MakeConstraint creates a new test Constraint.
func MakeConstraint(t testing.TB, kind, name string) *unstructured.Unstructured {
	t.Helper()

	u := &unstructured.Unstructured{Object: make(map[string]interface{})}

	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constraints.Group,
		Version: "v1beta1",
		Kind:    kind,
	})
	u.SetName(name)

	return u
}
