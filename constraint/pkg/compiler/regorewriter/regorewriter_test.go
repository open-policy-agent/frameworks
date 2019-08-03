package regorewriter

import (
	"strings"
	"testing"
	"text/template"

	"github.com/google/go-cmp/cmp"
)

const constraintTemplateTemplate = `
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

{{range .Aux}}
{{.}}
{{end}}
`

type CT struct {
	Package  string
	Imports  []string
	DenyBody string
	Aux      []string
}

func (c CT) String() string {
	tmpl, err := template.New("template").Parse(constraintTemplateTemplate)
	if err != nil {
		panic(err)
	}
	str := &strings.Builder{}
	if err := tmpl.Execute(str, c); err != nil {
		panic(err)
	}
	return str.String()
}

const libTemplate = `
package {{.Package}}

{{range .Imports}}
import {{.}}
{{end}}

{{.Body}}
`

type Lib struct {
	Package string
	Imports []string
	Body    string
}

func (l Lib) String() string {
	tmpl, err := template.New("template").Parse(libTemplate)
	if err != nil {
		panic(err)
	}
	str := &strings.Builder{}
	if err := tmpl.Execute(str, l); err != nil {
		panic(err)
	}
	return str.String()
}

func TestRegoRewriter(t *testing.T) {
	testcases := []struct {
		name string
		// libs     []string
		// externs  []string
		baseSrcs map[string]string
		libSrcs  map[string]string

		//
		wantError  bool
		wantResult map[string]string
	}{
		{
			name: "base imports lib and lib imports other lib",
			baseSrcs: map[string]string{
				"my_template.rego": CT{
					Package: "templates.stuff.MyTemplateV1",
					Imports: []string{"data.lib.alpha"},
					DenyBody: `
  alpha.check[input.name]
	data.lib.alpha.check[input.name]
`,
				}.String(),
			},
			libSrcs: map[string]string{
				"lib/alpha.rego": Lib{
					Package: "lib.alpha",
					Imports: []string{"data.lib.beta"},
					Body: `
check(objects) = object {
  object := objects[_]
  beta.check(object)
	data.lib.beta.check(object)
}
`,
				}.String(),
				"lib/beta.rego": Lib{
					Package: "lib.beta",
					Body: `
check(name) {
  name == "beta"
}
`,
				}.String(),
			},
			wantResult: map[string]string{
				"my_template.rego": `package templates.stuff.MyTemplateV1

import data.foo.bar.lib.alpha

deny[{
	"msg": message,
	"details": metadata,
}] {
	alpha.check[input.name]
	data.foo.bar.lib.alpha.check[input.name]
}
`,
				"lib/alpha.rego": `package foo.bar.lib.alpha

import data.foo.bar.lib.beta

check(objects) = object {
	object := objects[_]
	beta.check(object)
	data.foo.bar.lib.beta.check(object)
}
`,
				"lib/beta.rego": `package foo.bar.lib.beta

check(name) {
	name == "beta"
}
`,
			},
		},

		{
			name: "base references input",
			baseSrcs: map[string]string{
				"my_template.rego": CT{
					Package: "templates.stuff.MyTemplateV1",
					DenyBody: `
  bucket := input.asset.bucket
`,
				}.String(),
			},
			wantResult: map[string]string{
				"my_template.rego": `package templates.stuff.MyTemplateV1

deny[{
	"msg": message,
	"details": metadata,
}] {
	bucket := input.asset.bucket
}
`,
			},
		},
		{
			name: "lib references input",
			libSrcs: map[string]string{
				"lib/my_lib.rego": Lib{
					Package: "lib.myLib",
					Body: `
is_foo(name) {
  input.foo[name]
}
`,
				}.String(),
			},
			wantResult: map[string]string{
				"lib/my_lib.rego": `package foo.bar.lib.myLib

is_foo(name) {
	input.foo[name]
}
`,
			},
		},

		// Error cases
		{
			name: "base imports other base",
			baseSrcs: map[string]string{
				"my_template.rego": CT{
					Package: "templates.stuff.MyTemplateV1",
					Imports: []string{"data.stuff.YourTemplateV1"},
				}.String(),
				"your_template.rego": CT{
					Package: "templates.stuff.YourTemplateV1",
				}.String(),
			},
			wantError: true,
		},
		{
			name: "base references other base",
			baseSrcs: map[string]string{
				"my_template.rego": CT{
					Package: "templates.stuff.MyTemplateV1",
					DenyBody: `
  bucket := input.asset.bucket
  # invalid reference
  destination := data.templates.stuff.YourTemplateV1.destination_bucket(bucket)
`,
				}.String(),
				"your_template.rego": CT{
					Package: "templates.stuff.YourTemplateV1",
				}.String(),
			},
			wantError: true,
		},
		{
			name: "lib has invalid lib prefix",
			libSrcs: map[string]string{
				"lib/my_lib.rego": Lib{
					Package: "mystuff.myLib",
				}.String(),
			},
			wantError: true,
		},
		{
			name: "base references invalid extern",
			baseSrcs: map[string]string{
				"my_template.rego": CT{
					Package: "templates.stuff.MyTemplateV1",
					Aux: []string{`
is_fungible(name) {
  data.badextern.fungibles[name]
}
`},
				}.String(),
			},
			wantError: true,
		},
		{
			name: "lib references invalid extern",
			libSrcs: map[string]string{
				"lib/my_lib.rego": Lib{
					Package: "lib.myLib",
					Body: `
is_fungible(name) {
  data.badextern.fungibles[name]
}
`,
				}.String(),
			},
			wantError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pp := NewPackagePrefixer("foo.bar")
			libs := []string{"data.lib"}
			externs := []string{"data.inventory"}
			rr, err := New(pp, libs, externs)
			if err != nil {
				t.Fatalf("Failed to create %s", err)
			}

			// TODO: factor out code for filesystem testing
			for path, content := range tc.baseSrcs {
				if err := rr.AddBase(path, content); err != nil {
					// TODO: add testcase for failed parse
					t.Fatalf("failed to add base %s", path)
				}
			}
			for path, content := range tc.libSrcs {
				if err := rr.AddLib(path, content); err != nil {
					// TODO: add testcase for failed parse
					t.Fatalf("failed to add lib %s", path)
				}
			}
			// end TODO: factor out code for filesystem testing

			sources, err := rr.Rewrite()
			if tc.wantError {
				if err == nil {
					t.Errorf("wanted error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error during rewrite: %s", err)
			}

			result, err := sources.AsMap()
			if err != nil {
				t.Fatalf("unexpected error during Sources.AsMap: %s", err)
			}
			if diff := cmp.Diff(result, tc.wantResult); diff != "" {
				t.Errorf("result differs from desired:\n%s", diff)
			}
		})
	}
}
