package cts

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

const (
	ModuleDeny = `
package foo

violation contains {"msg": msg} if {
  true
  msg := "denied"
}
`
	MockTemplateName  string          = "fakes"
	MockTemplate      string          = "Fakes"
	MockTargetHandler string          = "foo"
	RegoVersion       ast.RegoVersion = ast.RegoV0
)

var defaults = []Opt{
	OptName(MockTemplateName),
	OptCRDNames(MockTemplate),
	OptTargets(TargetWithVersion(handlertest.TargetName, ModuleDeny, ast.RegoV1)),
}

func New(opts ...Opt) *templates.ConstraintTemplate {
	tmpl := &templates.ConstraintTemplate{}

	tmpl.Spec.CRD.Spec.Validation = &templates.Validation{}
	tmpl.Spec.CRD.Spec.Validation.OpenAPIV3Schema = &apiextensions.JSONSchemaProps{
		Type: "object",
	}

	opts = append(defaults, opts...)
	for _, opt := range opts {
		opt(tmpl)
	}
	return tmpl
}

type Opt func(*templates.ConstraintTemplate)

func OptName(name string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.ObjectMeta.Name = name
	}
}

func OptCRDNames(kind string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Names = templates.Names{
			Kind: kind,
		}
	}
}

func OptLabels(labels map[string]string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.ObjectMeta.Labels = labels
	}
}

func OptCRDSchema(pm PropMap) Opt {
	p := Prop(pm)
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Validation = &templates.Validation{}
		tmpl.Spec.CRD.Spec.Validation.OpenAPIV3Schema = &p
	}
}

func Target(name string, rego string, libs ...string) templates.Target {
	return templates.Target{
		Target: name,
		Code: []templates.Code{
			Code(schema.Name, (&schema.Source{
				Rego: rego,
				Libs: libs,
			}).ToUnstructured()),
		},
	}
}

func TargetWithVersion(name string, rego string, regoVersion ast.RegoVersion, libs ...string) templates.Target {
	return templates.Target{
		Target: name,
		Code: []templates.Code{
			Code(schema.Name, (&schema.Source{
				Rego:    rego,
				Version: regoVersion.String(),
				Libs:    libs,
			}).ToUnstructured()),
		},
	}
}

func Code(engine string, source interface{}) templates.Code {
	return templates.Code{
		Engine: engine,
		Source: &templates.Anything{
			Value: source,
		},
	}
}

func TargetCustomEngines(name string, codes ...templates.Code) templates.Target {
	target := templates.Target{Target: name}
	target.Code = append(target.Code, codes...)
	return target
}

func TargetNoEngine(name string) templates.Target {
	return templates.Target{
		Target: name,
		Code:   []templates.Code{},
	}
}

func OptTargets(targets ...templates.Target) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		cpy := make([]templates.Target, len(targets))
		copy(cpy, targets)

		// Use a copy to prevent crosstalk between tests.
		tmpl.Spec.Targets = cpy
	}
}
