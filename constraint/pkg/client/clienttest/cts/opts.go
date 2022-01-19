package cts

import (
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

const ModuleDeny = `
package foo

violation[{"msg": msg}] {
  true
  msg := "denied"
}
`

var defaults = []Opt{
	OptName("fakes"),
	OptCRDNames("Fakes"),
	OptTargets(Target(handlertest.HandlerName, ModuleDeny)),
}

func New(opts ...Opt) *templates.ConstraintTemplate {
	tmpl := &templates.ConstraintTemplate{}

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
	return templates.Target{Target: name, Rego: rego, Libs: libs}
}

func OptTargets(targets ...templates.Target) Opt {
	return func(tmpl *templates.ConstraintTemplate) {
		cpy := make([]templates.Target, len(targets))
		copy(cpy, targets)

		// Use a copy to prevent crosstalk between tests.
		tmpl.Spec.Targets = cpy
	}
}
