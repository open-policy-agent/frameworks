package clienttest

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
)

const (
	KindAllow            = "Allow"
	KindDeny             = "Deny"
	KindDenyPrint        = "DenyPrint"
	KindDenyImport       = "DenyImport"
	KindCheckData        = "CheckData"
	KindRuntimeError     = "RuntimeError"
	KindForbidDuplicates = "ForbidDuplicates"
	KindFuture           = "Future"
)

// ModuleAllow defines a Rego package which allows all objects it reviews.
const ModuleAllow = `
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
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: ModuleAllow,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

// ModuleDeny defines a Rego package which denies all objects it reviews.
const ModuleDeny = `
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
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: ModuleDeny,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

const moduleDenyPrint = `
package foo

violation[{"msg": msg}] {
  print("denied!")
  true
  msg := "denied"
}
`

func TemplateDenyPrint() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("denyprint")

	ct.Spec.CRD.Spec.Names.Kind = KindDenyPrint
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleDenyPrint,
					}).ToUnstructured(),
				},
			},
		},
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
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleImportDenyRego,
						Libs: []string{moduleImportDenyLib},
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

// moduleCheckData defines a Rego package which checks the "data" field of
// Objects under review.
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
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleCheckData,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

func KindCheckDataNumbered(i int) string {
	return fmt.Sprintf("%s-%d", KindCheckData, i)
}

func TemplateCheckDataNumbered(i int) *templates.ConstraintTemplate {
	ct := TemplateCheckData()

	kind := KindCheckDataNumbered(i)
	ct.SetName(strings.ToLower(kind))
	ct.Spec.CRD.Spec.Names.Kind = kind

	return ct
}

const moduleRuntimeError = `
package foo

message(arg) = output {
  output := 7
}

message(arg) = output {
  output := 5
}

violation[{"msg": msg}] {
  result := message("a")
  msg := sprintf("result is %v", [result])
}

`

func TemplateRuntimeError() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("runtimeerror")
	ct.Spec.CRD.Spec.Names.Kind = KindRuntimeError
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleRuntimeError,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

const moduleForbidDuplicates = `
package foo

violation[{"msg": msg}] {
  obj := data.inventory.cluster[_]
  gotData := input.review.object.data
  gotData == obj.data
  msg := sprintf("duplicate data %v", [gotData])
}
`

func TemplateForbidDuplicates() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("forbidduplicates")
	ct.Spec.CRD.Spec.Names.Kind = KindForbidDuplicates
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleForbidDuplicates,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

const moduleFuture = `
package foo

import future.keywords.in

violation[{"msg": msg}] {
  some n in ["1", "2"]
  n == input.review.object.data
  msg := "bad data"
}
`

func TemplateFuture() *templates.ConstraintTemplate {
	ct := &templates.ConstraintTemplate{}

	ct.SetName("future")
	ct.Spec.CRD.Spec.Names.Kind = KindFuture
	ct.Spec.CRD.Spec.Validation = &templates.Validation{
		OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
			Type: "object",
		},
	}

	ct.Spec.Targets = []templates.Target{{
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: moduleFuture,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}
