package cts

import (
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

func New(args ...Opt) *templates.ConstraintTemplate {
	tmpl := &templates.ConstraintTemplate{}
	for _, arg := range args {
		arg(tmpl)
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

func OptTargets(ts ...string) Opt {
	targets := make([]templates.Target, len(ts))
	for i, t := range ts {
		targets[i] = templates.Target{Target: t, Rego: `package hello violation[{"msg": msg}] {msg = "hello"}`}
	}

	return func(tmpl *templates.ConstraintTemplate) {
		tmpl.Spec.Targets = targets
	}
}
