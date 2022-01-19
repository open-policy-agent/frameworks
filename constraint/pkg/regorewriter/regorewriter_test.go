package regorewriter

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"text/template"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
)

const regoSrcTemplateText = `
package {{.Package}}

{{range .Imports}}
import {{.}}
{{end}}

{{if .DenyBody}}
deny[{
    "msg": message,
    "details": metadata,
}] {
    {{.DenyBody}}
}
{{end}}

{{.Body}}
`

var regoSrcTemplate *template.Template

func init() {
	var err error
	regoSrcTemplate, err = template.New("template").Parse(regoSrcTemplateText)
	if err != nil {
		panic(err)
	}
}

type regoSrc struct {
	Package  string
	Imports  []string
	DenyBody string
	Body     string
}

type RegoOption func(src *regoSrc)

func Body(b string) RegoOption {
	return func(src *regoSrc) {
		src.Body = b
	}
}

func DenyBody(db string) RegoOption {
	return func(src *regoSrc) {
		src.DenyBody = db
	}
}

func FuncBody(b string) RegoOption {
	return func(src *regoSrc) {
		src.Body = fmt.Sprintf(`
myfunc() {
  %s
}
`, b)
	}
}

func Import(i ...string) RegoOption {
	return func(src *regoSrc) {
		src.Imports = i
	}
}

func RegoSrc(pkg string, opts ...RegoOption) string {
	rs := regoSrc{
		Package: pkg,
	}
	for _, opt := range opts {
		opt(&rs)
	}
	str := &strings.Builder{}
	if err := regoSrcTemplate.Execute(str, rs); err != nil {
		panic(err)
	}
	return str.String()
}

// RegoRewriterTestcase is a testcase for rewriting rego.
type RegoRewriterTestcase struct {
	name      string            // testcase name
	baseSrcs  map[string]string // entrypoint files
	libSrcs   map[string]string // lib files
	wantError error             // error returned when RegoRewriter should reject input
}

func MockRegoWriter() (*RegoRewriter, error) {
	pp := NewPackagePrefixer("foo.bar")
	libs := []string{"data.lib"}
	externs := []string{"data.inventory"}
	return New(pp, libs, externs)
}

func (tc *RegoRewriterTestcase) Run(t *testing.T) {
	rr, err := MockRegoWriter()
	if err != nil {
		t.Fatalf("Failed to create %s", err)
	}
	for path, content := range tc.baseSrcs {
		if err := rr.AddEntryPoint(path, content); err != nil {
			t.Fatalf("unexpected error during AddEntryPoint: %s", err)
		}
	}
	for path, content := range tc.libSrcs {
		if err := rr.AddLib(path, content); err != nil {
			t.Logf("unexpected error during AddLib %v", err)
			return
		}
	}

	_, err = rr.Rewrite()
	if tc.wantError != nil {
		if !errors.Is(err, tc.wantError) {
			t.Errorf("Rewrite() got error = %v, want %v", err, tc.wantError)
		}
		return
	}
}

func TestRegoRewriterErrorCases(t *testing.T) {
	testcases := []struct {
		name      string
		imports   string
		snippet   string
		wantError error
	}{
		{
			name:      "invalid data object reference",
			snippet:   "data.badextern.fungibles[name]",
			wantError: ErrDataReferences,
		},
		{
			name:      "import invalid lib",
			imports:   "data.stuff.foolib",
			snippet:   "foolib.check(input)",
			wantError: ErrInvalidImport,
		},
		{
			name:      "import invalid lib path",
			imports:   "data.stuff.foolib",
			snippet:   "foolib.check(input)",
			wantError: ErrInvalidImport,
		},
		{
			name: "invalid binding of data to var",
			snippet: `
	x := data
	x.stuff.more.stuff
`,
			wantError: ErrDataReferences,
		},
		{
			name: "invalid reference of data object with key var",
			snippet: `
	x := input.name
	y := data[x]
`,
			wantError: ErrDataReferences,
		},
		{
			name: "invalid reference of data object with key literal",
			snippet: `
	y := data["foo"]
`,
			wantError: ErrDataReferences,
		},
		{
			name:    "invalid import of input",
			imports: "input.metadata",
			snippet: `
	metadata.x == "abc"
`,
			wantError: ErrInvalidImport,
		},
		{
			name:    "invalid assignment to data using with from var",
			imports: "data.lib.util",
			snippet: `
	util with data.checks as data.lib.mychecks
`,
			wantError: ErrDataReferences,
		},
		{
			name:    "invalid assignment to data using with from literal",
			imports: "data.lib.util",
			snippet: `
	util with data.bobs as {"dev": ["bob"]}
`,
			wantError: ErrDataReferences,
		},
	}

	for _, tc := range testcases {
		for _, srcTypeMeta := range []struct {
			name           string
			pkg            string
			snippetBuilder func(string) RegoOption
			srcSetter      func(*RegoRewriterTestcase, string)
		}{
			{
				name:           "entrypoint",
				pkg:            "template.stuff.MyTemplateV1",
				snippetBuilder: DenyBody,
				srcSetter: func(tc *RegoRewriterTestcase, src string) {
					tc.baseSrcs["my_template.rego"] = src
				},
			},
			{
				name:           "lib",
				pkg:            "lib.fail",
				snippetBuilder: FuncBody,
				srcSetter: func(tc *RegoRewriterTestcase, src string) {
					tc.libSrcs["my_lib.rego"] = src
				},
			},
		} {
			var opts []RegoOption
			if tc.imports != "" {
				opts = append(opts, Import(tc.imports))
			}
			opts = append(opts, srcTypeMeta.snippetBuilder(tc.snippet))

			subTc := RegoRewriterTestcase{
				name:      tc.name,
				wantError: tc.wantError,
				baseSrcs:  map[string]string{},
				libSrcs:   map[string]string{},
			}
			srcTypeMeta.srcSetter(&subTc, RegoSrc(srcTypeMeta.pkg, opts...))
			t.Run(fmt.Sprintf("%s-%s", srcTypeMeta.name, tc.name), subTc.Run)
		}
	}
}

func TestRegoRewriterRewriteDataRef(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		imports string
		lib     []string
		extern  []string
		want    string
	}{
		{
			name:    "no rewrite when data ref is an external reference",
			prefix:  "foo.bar",
			extern:  []string{"data.ext", "data.inventory"},
			imports: "data.ext",
			want:    "data.ext",
		},
		{
			name:    "no rewrite for non data ref",
			prefix:  "foo.bar",
			extern:  []string{"data.inventory"},
			imports: "invalid_data.name",
			want:    "invalid_data.name",
		},
		{
			name:    "rewrite for ref is sub of external references",
			prefix:  "foo.bar",
			extern:  []string{"data.ext.util"},
			imports: "data.ext",
			want:    "data.foo.bar.ext",
		},
		{
			name:    "add prefix for data ref",
			prefix:  "foo.bar",
			extern:  []string{"data.inventory"},
			imports: "data.some_ref",
			want:    "data.foo.bar.some_ref",
		},
		{
			name:    "rewrite for ref same as libs",
			prefix:  "foo.bar",
			lib:     []string{"data.lib"},
			imports: "data.lib",
			want:    "data.foo.bar.lib",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(NewPackagePrefixer(tt.prefix), tt.lib, tt.extern)
			if err != nil {
				t.Fatalf("Failed to create RegoRewriter %v", err)
			}
			ref, err := ast.ParseRef(tt.imports)
			if err != nil {
				t.Fatalf("got ast.ParseRef(%q) error = %v, want nil", tt.imports, err)
			}
			wantRef, err := ast.ParseRef(tt.want)
			if err != nil {
				t.Fatalf("got ast.ParseRef(%q) error = %v, want nil", tt.want, err)
			}
			if got := r.rewriteDataRef(ref); !got.Equal(wantRef) {
				t.Errorf("rewriteDataRef() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddEntryPointParseErrors(t *testing.T) {
	tcs := []struct {
		name      string
		path      string
		src       string
		wantError error
	}{
		{
			name: "add lib.rego path",
			path: "data.stuff.foolib",
			src: `package lib.rego

test_ok {
	true
}
`,
		},
		{
			name: "add invalid rego",
			path: "invalidrego",
			src: `package lib.rego
something invalid`,
			wantError: ErrInvalidModule,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := MockRegoWriter()
			if err != nil {
				t.Fatalf("Failed to create RegoRewriter %q", err)
			}
			if gotErr := rr.AddEntryPoint(tc.path, tc.src); !errors.Is(gotErr, tc.wantError) {
				t.Errorf("got AddEntryPoint() error = %q, want %v", gotErr, tc.wantError)
			}
		})
	}
}

func TestRegoRewriterAddPathFromFs(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "path not exist",
			path:    "foo/bar",
			wantErr: ErrReadingFile,
		},
		{
			name: "path with test folder",
			path: ".",
		},
		{
			name: "path without test",
			path: "../../",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := MockRegoWriter()
			if err != nil {
				t.Fatalf("Failed to create RegoRewriter %q", err)
			}
			if err := rr.AddLibFromFs(tc.path); !errors.Is(err, tc.wantErr) {
				t.Errorf("AddLibFromFs() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err := rr.AddBaseFromFs(tc.path); !errors.Is(err, tc.wantErr) {
				t.Errorf("AddBaseFromFs() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRegoRewriteEntryPoint(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		content    string
		wantResult map[string]string
	}{
		{
			name:   "entry point imports lib",
			prefix: "prefix.path",
			content: `package lib.alpha
import data.lib.alpha
violation[{"msg":msg}] {
	x := data.lib.alpha
	y := data.lib.alpha.ext[_]
	z := "data.lib.alpha"
	data.lib.alpha.check[input.name]
	ex := data.ext.alpha
}`,
			wantResult: map[string]string{"path": `package lib.alpha

import data.prefix.path.lib.alpha

violation[{"msg": msg}] {
	x := data.prefix.path.lib.alpha
	y := data.prefix.path.lib.alpha.ext[_]
	z := "data.lib.alpha"
	data.prefix.path.lib.alpha.check[input.name]
	ex := data.ext.alpha
}
`},
		}, {
			name:   "entry point binds data.lib to var",
			prefix: "prefix",
			content: `package templates.stuff.MyTemplateV1
import data.lib.alpha
violation[{"msg":msg}] {
	x := data.lib
	y := x[_]
}`,
			wantResult: map[string]string{"path": `package templates.stuff.MyTemplateV1

import data.prefix.lib.alpha

violation[{"msg": msg}] {
	x := data.prefix.lib
	y := x[_]
}
`},
		}, {
			name:   "entry point uses data.lib[_]",
			prefix: "prefix",
			content: `package templates.stuff.MyTemplateV1
import data.lib.alpha
violation[{"msg":msg}] {
	x := data.lib[_]
}`,
			wantResult: map[string]string{"path": `package templates.stuff.MyTemplateV1

import data.prefix.lib.alpha

violation[{"msg": msg}] {
	x := data.prefix.lib[_]
}
`},
		}, {
			name:   "entry point references input",
			prefix: "prefix",
			content: `package templates.stuff.MyTemplateV1
violation[{"msg":msg}] {
	bucket := input.asset.bucket
}`,
			wantResult: map[string]string{"path": `package templates.stuff.MyTemplateV1

violation[{"msg": msg}] {
	bucket := input.asset.bucket
}
`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := New(NewPackagePrefixer(tc.prefix), []string{"data.lib"}, []string{"data.ext"})
			if err != nil {
				t.Fatalf("Failed to create RegoRewriter %s", err)
			}
			if err := rr.AddEntryPoint("path", tc.content); err != nil {
				t.Fatalf("failed to add base source %q", err)
				return
			}
			sources, err := rr.Rewrite()
			if err != nil {
				t.Fatalf("Rewrite() got error = %v, want nil", err)
			}

			result, err := sources.AsMap()
			if err != nil {
				t.Fatalf("unexpected error during Sources.AsMap: %s", err)
			}

			if diff := cmp.Diff(tc.wantResult, result); diff != "" {
				t.Errorf("result differs from desired:\n%s", diff)
			}
		})
	}
}

func TestRegoRewriteLib(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		content    string
		wantResult map[string]string
		wantError  error
	}{
		{
			name:   "entry point imports lib",
			prefix: "prefix.path",
			content: `package lib.alpha
import data.lib.alpha
check(objects) = object {
	object := objects[_]
	beta.check(object)
	data.lib.beta.check(object)
}`,
			wantResult: map[string]string{"path": `package prefix.path.lib.alpha

import data.prefix.path.lib.alpha

check(objects) = object {
	object := objects[_]
	beta.check(object)
	data.prefix.path.lib.beta.check(object)
}
`},
		}, {
			name:   "entry point binds data.lib to var",
			prefix: "prefix",
			content: `package lib.mylib
myfunc() {
	x := data.lib
	y := x[_]
}`,
			wantResult: map[string]string{"path": `package prefix.lib.mylib

myfunc {
	x := data.prefix.lib
	y := x[_]
}
`},
		}, {
			name:   "lib uses data.lib[_]",
			prefix: "prefix",
			content: `package lib.alpha
check(object) {
	x := data.lib[_]
	object == "foo"
}`,
			wantResult: map[string]string{"path": `package prefix.lib.alpha

check(object) {
	x := data.prefix.lib[_]
	object == "foo"
}
`},
		}, {
			name:   "lib references input",
			prefix: "prefix",
			content: `package lib.myLib
is_foo(name) {
	input.foo[name]
}`,
			wantResult: map[string]string{"path": `package prefix.lib.myLib

is_foo(name) {
	input.foo[name]
}
`},
		}, {
			name:   "walk data.lib",
			prefix: "prefix",
			content: `package lib.myLib
is_foo(name) {
	walk(data.lib, [p, v])
}`,
			wantResult: map[string]string{"path": `package prefix.lib.myLib

is_foo(name) {
	walk(data.prefix.lib, [p, v])
}
`},
		}, {
			name:      "lib cannot have package name data.lib",
			prefix:    "prefix",
			content:   `package lib`,
			wantError: ErrInvalidLibs,
		}, {
			name:      "lib has invalid package prefix",
			prefix:    "prefix",
			content:   `package mystuff.myLib`,
			wantError: ErrInvalidLibs,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := New(NewPackagePrefixer(tc.prefix), []string{"data.lib"}, []string{"data.ext"})
			if err != nil {
				t.Fatalf("Failed to create RegoRewriter %s", err)
			}
			if err := rr.AddLib("path", tc.content); err != nil {
				t.Fatalf("failed to add lib source %q", err)
			}
			sources, err := rr.Rewrite()
			if err != nil {
				if !errors.Is(err, tc.wantError) {
					t.Errorf("Rewrite() got error = %v, want = %v", err, tc.wantError)
				} else {
					return
				}
			}

			result, err := sources.AsMap()
			if err != nil {
				t.Fatalf("unexpected error during Sources.AsMap: %s", err)
			}

			if diff := cmp.Diff(tc.wantResult, result); diff != "" {
				t.Errorf("result differs from desired:\n%s", diff)
			}
		})
	}
}
