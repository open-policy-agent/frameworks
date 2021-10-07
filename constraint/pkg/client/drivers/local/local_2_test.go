package local

import (
	"context"
	"errors"
	"github.com/open-policy-agent/opa/storage"
	"sort"
	"strings"
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

			wantErr:     ErrModulePrefix,
			wantModules: nil,
		},
		{
			name:   "module prefix with separator",
			prefix: "a_idx_b",
			srcs:   []string{},

			wantErr:     ErrModulePrefix,
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

			wantErr:     ErrParse,
			wantModules: nil,
		},
		{
			name:   "add uncompilable module",
			prefix: "foo",
			srcs:   []string{UncompilableModule},

			wantErr:     ErrCompile,
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
			ctx := context.Background()

			d := New()

			for prefix, src := range tc.beforeModules {
				err := d.PutModules(ctx, prefix, src)
				if err != nil {
					t.Fatal(err)
				}
			}

			dr, ok := d.(*driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &driver{})
			}

			gotErr := d.PutModules(ctx, tc.prefix, tc.srcs)
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

func TestDriver_PutModules_StorageErrors(t *testing.T) {
	testCases := []struct {
		name    string
		storage storage.Store

		wantErr bool
	}{
		{
			name: "success",
			storage: &fakeStorage{},
			wantErr: false,
		},
		{
			name: "failure to create transaction",
			storage: &transactionErrorStorage{},
			wantErr: true,
		},
		{
			name: "failure to upsert policy",
			storage: &upsertErrorStorage{},
			wantErr: true,
		},
		{
			name: "failure to commit policy",
			storage: &commitErrorStorage{},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New(ArgStorage(tc.storage))

			err := d.PutModule(ctx, "foo", Module)

			if tc.wantErr && err == nil {
				t.Fatalf("got PutModule() err %v, want error", nil)
			} else if !tc.wantErr && err != nil {
				t.Fatalf("got PutModule() err %v, want %v", err, nil)
			}

			dr, ok := d.(*driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &driver{})
			}

			gotModules := getModules(dr)

			var wantModules []string
			if !tc.wantErr {
				wantModules = []string{"foo"}
			}

			if diff := cmp.Diff(wantModules, gotModules, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func TestDriver_DeleteModule(t *testing.T) {
	testCases := []struct {
		name string
		beforeModules map[string][]string

		moduleName string

		wantErr error
		wantModules []string
	}{
		{
			name: "invalid module name",
			moduleName: "",

			wantErr: ErrModuleName,
			wantModules: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

		})
	}
}

func TestDriver_DeleteModule_StorageErrors(t *testing.T) {
	testCases := []struct {
		name string
		storage storage.Store

		wantErr bool
	}{
		{
			name: "success",
			storage: &fakeStorage{},
			wantErr: false,
		},
		{
			name: "failure to delete policy",
			storage: &deleteErrorStorage{},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			d := New(ArgStorage(tc.storage))

			err := d.PutModule(ctx, "foo", Module)
			if err != nil {
				t.Fatal(err)
			}

			_, err = d.DeleteModule(ctx, "foo")

			if tc.wantErr && err == nil {
				t.Fatalf("got DeleteModule() err %v, want error", nil)
			} else if !tc.wantErr && err != nil {
				t.Fatalf("got DeleteModule() err %v, want %v", err, nil)
			}

			dr, ok := d.(*driver)
			if !ok {
				t.Fatalf("got New() type = %T, want %T",
					d, &driver{})
			}

			gotModules := getModules(dr)

			var wantModules []string
			if tc.wantErr {
				wantModules = []string{"foo"}
			}

			if diff := cmp.Diff(wantModules, gotModules, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func getModules(dr *driver) []string {
	result := make([]string, len(dr.modules))

	idx := 0
	for module := range dr.modules {
		result[idx] = module
		idx++
	}

	sort.Strings(result)
	return result
}

type fakeStorage struct {
	storage.Store

	policies map[string][]byte
	values   map[string]interface{}
}

var _ storage.Store = &fakeStorage{}

func (s *fakeStorage) UpsertPolicy(ctx context.Context, transaction storage.Transaction, name string, bytes []byte) error {
	if s.policies == nil {
		s.policies = make(map[string][]byte)
	}

	s.policies[name] = bytes

	return nil
}

func (s *fakeStorage) DeletePolicy(ctx context.Context, transaction storage.Transaction, name string) error {
	delete(s.policies, name)

	return nil
}

func (s *fakeStorage) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, nil
}

func (s *fakeStorage) Read(ctx context.Context, txn storage.Transaction, path storage.Path) (interface{}, error) {
	value, found := s.values[strings.Join(path, ".")]
	if !found {
		return nil, &storage.Error{Code: storage.NotFoundErr}
	}

	return value, nil
}

func (s *fakeStorage) Write(ctx context.Context, txn storage.Transaction, op storage.PatchOp, path storage.Path, value interface{}) error {
	if s.values == nil {
		s.values = make(map[string]interface{})
	}

	s.values[strings.Join(path, ".")] = value

	return nil
}

func (s *fakeStorage) Commit(ctx context.Context, txn storage.Transaction) error {
	return nil
}

func (s *fakeStorage) Abort(ctx context.Context, txn storage.Transaction) {}

type transactionErrorStorage struct {
	fakeStorage
}

func (s *transactionErrorStorage) NewTransaction(ctx context.Context, params ...storage.TransactionParams) (storage.Transaction, error) {
	return nil, errors.New("error making new transaction")
}

type upsertErrorStorage struct {
	fakeStorage
}

func (s *upsertErrorStorage) UpsertPolicy(ctx context.Context, transaction storage.Transaction, name string, bytes []byte) error {
	return errors.New("error upserting policy")
}

type commitErrorStorage struct {
	fakeStorage
}

func (s *commitErrorStorage) Commit(ctx context.Context, txn storage.Transaction) error {
	return errors.New("error committing changes")
}

type deleteErrorStorage struct {
	fakeStorage
}

func (s *deleteErrorStorage) DeletePolicy(ctx context.Context, transaction storage.Transaction, name string) error {
	return errors.New("error deleting policy")
}
