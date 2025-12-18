package cts

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

const (
	// ModuleDeny is a Rego module that denies all objects.
	ModuleDeny = `
package foo

violation contains {"msg": msg} if {
  true
  msg := "denied"
}
`
	// MockTemplateName is the default template name for tests.
	MockTemplateName string = "fakes"
	// MockTemplate is the default template kind for tests.
	MockTemplate string = "Fakes"
	// MockTargetHandler is the default target handler for tests.
	MockTargetHandler string = "foo"
	// RegoVersion is the default Rego version for tests.
	RegoVersion ast.RegoVersion = ast.RegoV0
)

var defaults = []Opt{
	OptName(MockTemplateName),
	OptCRDNames(MockTemplate),
	OptTargets(TargetWithVersion(handlertest.TargetName, ModuleDeny, ast.RegoV1)),
}

// New creates a new ConstraintTemplate with the given options.
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

// Opt is a function that configures a ConstraintTemplate.
type Opt func(*templates.ConstraintTemplate)

// OptName sets the name of the ConstraintTemplate.
func OptName(name string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Name = name
	}
}

// OptCRDNames sets the CRD kind name.
func OptCRDNames(kind string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Names = templates.Names{
			Kind: kind,
		}
	}
}

// OptLabels sets labels on the ConstraintTemplate.
func OptLabels(labels map[string]string) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Labels = labels
	}
}

// OptCRDSchema sets the OpenAPI schema for constraint parameters.
func OptCRDSchema(pm PropMap) Opt {
	p := Prop(pm)
	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Spec.CRD.Spec.Validation = &templates.Validation{}
		tmpl.Spec.CRD.Spec.Validation.OpenAPIV3Schema = &p
	}
}

// Target creates a Target with Rego code.
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

// TargetWithVersion creates a Target with Rego code and a specific version.
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

// Code creates a Code block with the given engine and source.
func Code(engine string, source interface{}) templates.Code {
	return templates.Code{
		Engine: engine,
		Source: &templates.Anything{
			Value: source,
		},
	}
}

// TargetCustomEngines creates a Target with custom engine codes.
func TargetCustomEngines(name string, codes ...templates.Code) templates.Target {
	target := templates.Target{Target: name}
	target.Code = append(target.Code, codes...)
	return target
}

// TargetNoEngine creates a Target with no engine codes.
func TargetNoEngine(name string) templates.Target {
	return templates.Target{
		Target: name,
		Code:   []templates.Code{},
	}
}

// OptTargets sets the targets for the ConstraintTemplate.
func OptTargets(targets ...templates.Target) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		cpy := make([]templates.Target, len(targets))
		copy(cpy, targets)

		// Use a copy to prevent crosstalk between tests.
		tmpl.Spec.Targets = cpy
	}
}
