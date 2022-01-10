package clienttest

import (
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
)

const (
	KindAllow      = "Allow"
	KindDeny       = "Deny"
	KindDenyImport = "DenyImport"
	KindCheckData  = "CheckData"
)

// moduleAllow defines a Rego package which allows all objects it reviews.
const moduleAllow = `
package foo

violation[{"msg": msg}] {
  false
  msg := "denied"
}
`

func TemplateAllow() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("allow")

	ct.Spec.CRD.Spec.Names.Kind = KindAllow
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: HandlerName,
		Rego:   moduleAllow,
	}}

	return ct
}

// moduleDeny defines a Rego package which denies all objects it reviews.
const moduleDeny = `
package foo

violation[{"msg": msg}] {
  true
  msg := "denied"
}
`

func TemplateDeny() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("deny")

	ct.Spec.CRD.Spec.Names.Kind = KindDeny
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: HandlerName,
		Rego:   moduleDeny,
	}}

	return ct
}

const moduleImportDenyRego = `
package foo

import data.lib.bar

violation[{"msg": msg}] {
  bar.always[x]
  x == "imported"
  msg := "denied with library"
}
`

const moduleImportDenyLib = `
package lib.bar

always[y] {
  y = "imported"
}
`

// TemplateDenyImport returns a ConstraintTemplate which rejects all incoming
// objects and relies on a library to do so.
func TemplateDenyImport() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("denyimport")
	ct.Spec.CRD.Spec.Names.Kind = KindDenyImport
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: HandlerName,
		Rego:   moduleImportDenyRego,
		Libs:   []string{moduleImportDenyLib},
	}}

	return ct
}

// moduleCheckData defines a Rego package which checks the "data" field of
// Objects under review.
// TODO: Also test "details" wiring.
const moduleCheckData = `
package foo

violation[{"msg": msg, "details": details}] {
  wantData := input.parameters.wantData
  gotData := object.get(input.review.object, "data", "")
  wantData != gotData
  msg := sprintf("got %v but want %v for data", [gotData, wantData])
  details := {"got": gotData}
}
`

func TemplateCheckData() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("checkdata")
	ct.Spec.CRD.Spec.Names.Kind = KindCheckData
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: HandlerName,
		Rego:   moduleCheckData,
	}}

	return ct
}
