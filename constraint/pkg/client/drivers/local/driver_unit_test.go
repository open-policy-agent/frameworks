package local

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"
	clienterrors "github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	Module string = `
package foobar

fooisbar[msg] {
  input.foo == "bar"
  msg := "input.foo is bar"
}
`
)

func TestDriver_AddTemplate(t *testing.T) {
	testCases := []struct {
		name          string
		rego          string
		targetHandler string
		externs       []string

		wantErr       error
		wantCompilers map[string][]string
	}{
		{
			name:          "no target",
			wantErr:       clienterrors.ErrInvalidConstraintTemplate,
			wantCompilers: map[string][]string{},
		},
		{
			name:          "rego missing violation",
			targetHandler: cts.MockTargetHandler,
			rego:          Module,
			wantErr:       clienterrors.ErrInvalidConstraintTemplate,
			wantCompilers: map[string][]string{},
		},
		{
			name:          "valid template",
			targetHandler: cts.MockTargetHandler,
			rego: `
package something

violation[{"msg": "msg"}] {
  msg := "always"
}
`,
			wantCompilers: map[string][]string{"foo": {"Fakes"}},
		},
		{
			name:          "inventory disallowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			wantErr: clienterrors.ErrInvalidConstraintTemplate,
		},
		{
			name:          "inventory allowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs:       []string{"inventory"},
			wantErr:       nil,
			wantCompilers: map[string][]string{"foo": {"Fakes"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(Externs(tc.externs...))
			if err != nil {
				t.Fatal(err)
			}

			tmpl := cts.New(cts.OptTargets(cts.Target(tc.targetHandler, tc.rego)))
			gotErr := d.AddTemplate(tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
			}

			gotCompilers := listCompilers(d)

			if diff := cmp.Diff(tc.wantCompilers, gotCompilers, cmpopts.EquateEmpty()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func listCompilers(d *Driver) map[string][]string {
	gotCompilers := make(map[string][]string)

	for target, targetCompilers := range d.compilers.list() {
		for kind := range targetCompilers {
			gotCompilers[target] = append(gotCompilers[target], kind)
		}
		sort.Strings(gotCompilers[target])
	}

	return gotCompilers
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
			targetHandler: cts.MockTargetHandler,
			rego: `
package something

violation[{"msg": msg}] {msg := "always"}`,
		},
		{
			name:          "inventory allowed template",
			targetHandler: cts.MockTargetHandler,
			rego: `package something

violation[{"msg": "msg"}] {
	data.inventory = "something_else"
}`,
			externs: []string{"inventory"},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(Externs(tc.externs...))
			if err != nil {
				t.Fatal(err)
			}

			tmpl := cts.New(cts.OptTargets(cts.Target(tc.targetHandler, tc.rego)))
			gotErr := d.AddTemplate(tmpl)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("got AddTemplate() error = %v, want %v", gotErr, tc.wantErr)
			}

			if len(d.compilers.list()) == 0 {
				t.Errorf("driver failed to add module")
			}

			ctx := context.Background()
			gotErr = d.RemoveTemplate(ctx, tmpl)
			if gotErr != nil {
				t.Errorf("err = %v; want nil", gotErr)
			}

			gotCompilers := listCompilers(d)
			wantCompilers := map[string][]string{}

			if diff := cmp.Diff(wantCompilers, gotCompilers); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestDriver_PutData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  []string
		beforeValue interface{}
		path        []string
		value       interface{}

		wantErr error
	}{
		{
			name:  "root path",
			path:  []string{},
			value: map[string]interface{}{},

			wantErr: clienterrors.ErrPathInvalid,
		},
		{
			name:  "valid write",
			path:  []string{"foo"},
			value: map[string]interface{}{"foo": "bar"},

			wantErr: nil,
		},
		{
			name:        "valid overwrite",
			beforePath:  []string{"foo"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
		{
			name:        "write to subdirectory of existing data",
			beforePath:  []string{"foo"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo", "bar"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
		{
			name:        "write to subdirectory of non-object",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"foo", "bar"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: clienterrors.ErrWrite,
		},
		{
			name:        "write to parent directory of existing data",
			beforePath:  []string{"foo", "bar"},
			beforeValue: map[string]interface{}{"foo": "bar"},
			path:        []string{"foo"},
			value:       map[string]interface{}{"foo": "qux"},

			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := inmem.New()
			d, err := New(Storage(s))
			if err != nil {
				t.Fatal(err)
			}

			if tc.beforeValue != nil {
				err := d.AddData(ctx, tc.beforePath, tc.beforeValue)
				if err != nil {
					t.Fatalf("got setup PutData() error = %v, want %v", err, nil)
				}
			}

			err = d.AddData(ctx, tc.path, tc.value)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got PutData() error = %v, want %v",
					err, tc.wantErr)
			}

			if errors.Is(tc.wantErr, clienterrors.ErrPathInvalid) {
				return
			}

			// Verify the state of data in storage.

			wantValue := tc.value
			wantPath := tc.path
			if tc.wantErr != nil {
				// We encountered an error writing data, so we expect the original data to be unchanged.
				wantPath = tc.beforePath
				wantValue = tc.beforeValue
			}

			txn, err := s.NewTransaction(ctx)
			if err != nil {
				t.Fatal(err)
			}

			gotValue, err := s.Read(ctx, txn, wantPath)
			if err != nil {
				t.Fatalf("got fakeStorage.Read() error = %v, want %v", err, nil)
			}

			err = s.Commit(ctx, txn)
			if err != nil {
				t.Fatal(err)
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

			d, err := New(Storage(tc.storage))
			if err != nil {
				t.Fatal(err)
			}

			path := []string{"foo"}
			value := map[string]string{"bar": "qux"}
			err = d.AddData(ctx, path, value)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got PutData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriver_DeleteData(t *testing.T) {
	testCases := []struct {
		name        string
		beforePath  []string
		beforeValue interface{}
		path        []string

		wantDeleted bool
		wantErr     error
	}{
		{
			name:        "cannot delete root",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{},

			wantDeleted: false,
			wantErr:     clienterrors.ErrWrite,
		},
		{
			name:        "success",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"foo"},

			wantDeleted: true,
			wantErr:     nil,
		},
		{
			name:        "non existent",
			beforePath:  []string{"foo"},
			beforeValue: "bar",
			path:        []string{"qux"},

			wantDeleted: false,
			wantErr:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			s := inmem.New()
			d, err := New(Storage(s))
			if err != nil {
				t.Fatal(err)
			}

			err = d.AddData(ctx, tc.beforePath, tc.beforeValue)
			if err != nil {
				t.Fatalf("got setup PutData() error = %v, want %v", err, nil)
			}

			err = d.RemoveData(ctx, tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got DeleteData() error = %v, want %v", err, tc.wantErr)
			}

			var wantValue interface{}
			if !tc.wantDeleted {
				wantValue = tc.beforeValue
			}

			txn, err := s.NewTransaction(ctx)
			if err != nil {
				t.Fatal(err)
			}

			gotValue, err := s.Read(ctx, txn, tc.beforePath)
			if tc.wantDeleted {
				if !storage.IsNotFound(err) {
					t.Fatalf("got err %v, want not found", err)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			err = s.Commit(ctx, txn)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(wantValue, gotValue); diff != "" {
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

			d, err := New(Storage(tc.storage))
			if err != nil {
				t.Fatal(err)
			}

			path := []string{"foo"}
			err = d.RemoveData(ctx, path)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got DeleteData() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDriver_Externs_Intersection(t *testing.T) {
	tcs := []struct {
		name      string
		allowed   []Arg
		want      []string
		wantError error
	}{
		{
			name: "No Externs specified",
			want: []string{"data.inventory"},
		},
		{
			name:    "Empty Externs Used",
			allowed: []Arg{Externs()},
			want:    []string{},
		},
		{
			name:    "Inventory Used",
			allowed: []Arg{Externs("inventory")},
			want:    []string{"data.inventory"},
		},
		{
			name:      "Invalid Data Field",
			allowed:   []Arg{Externs("no_overlap")},
			want:      []string{},
			wantError: clienterrors.ErrCreatingDriver,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.allowed...)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got NewClient() error = %v, want %v",
					err, tc.wantError)
			}

			if tc.wantError != nil {
				return
			}

			if diff := cmp.Diff(tc.want, d.compilers.externs); diff != "" {
				t.Error(diff)
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

func TestDriver_AddConstraint(t *testing.T) {
	tests := []struct {
		name             string
		beforeConstraint *unstructured.Unstructured
		constraint       *unstructured.Unstructured
		wantParameters   map[string]interface{}
		wantError        error
	}{
		{
			name: "add constraint",
			constraint: cts.MakeConstraint(t, "Foo", "foo-1",
				cts.WantData("bar")),
			wantParameters: map[string]interface{}{
				"wantData": "bar",
			},
		},
		{
			name: "nil parameters",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Foo",
					"metadata": map[string]interface{}{
						"name": "foo-1",
					},
					"spec": map[string]interface{}{
						"parameters": nil,
					},
				},
			},
			wantParameters: map[string]interface{}{},
		},
		{
			name: "invalid parameters",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Foo",
					"metadata": map[string]interface{}{
						"name": "foo-1",
					},
					"spec": "invalid",
				},
			},
			wantParameters: nil,
			wantError:      constraints.ErrInvalidConstraint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New()
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if tt.beforeConstraint != nil {
				err = d.AddConstraint(ctx, tt.beforeConstraint)
				if err != nil {
					t.Fatal(err)
				}
			}

			err = d.AddConstraint(ctx, tt.constraint)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("got AddConstraint error = %v, want %v",
					err, tt.wantError)
			}

			compiler := ast.NewCompiler()
			module, err := ast.ParseModule("", `package foo`)
			if err != nil {
				t.Fatal(err)
			}
			compiler.Compile(map[string]*ast.Module{
				"foo": module,
			})

			key := fmt.Sprintf("%s[%q]", tt.constraint.GetKind(), tt.constraint.GetName())

			result, _, err := d.eval(ctx, compiler, []string{"constraints", key}, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.wantParameters == nil {
				if len(result) != 0 {
					t.Fatalf("want no parameters stored but got %+v", result)
				}
				return
			}

			gotParameters := result[0].Expressions[0].Value

			if diff := cmp.Diff(tt.wantParameters, gotParameters); diff != "" {
				t.Fatal(diff)
			}

			err = d.RemoveConstraint(ctx, tt.constraint)
			if err != nil {
				t.Fatal(err)
			}

			result2, _, err := d.eval(ctx, compiler, []string{"constraints", key}, nil)
			if err != nil {
				t.Fatal(err)
			}

			if len(result2) != 0 {
				t.Fatalf("want no parameters stored after deletion but got %+v", result)
			}
		})
	}
}
