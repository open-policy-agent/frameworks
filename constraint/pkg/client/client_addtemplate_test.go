package client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

var modules = []struct {
	name   string
	module string
	libs   []string
}{
	{
		name:   "Simple",
		module: moduleSimple,
		libs:   nil,
	},
	{
		name:   "Complex",
		module: moduleComplex,
		libs:   nil,
	},
	{
		name:   "Very Complex",
		module: moduleVeryComplex,
		libs:   []string{libVeryComplex},
	},
	{
		name:   "Simple Rego V1",
		module: moduleSimpleV1,
		libs:   nil,
	},
	{
		name:   "Complex Rego V1",
		module: moduleComplexV1,
		libs:   nil,
	},
	{
		name:   "Very Complex Rego V1",
		module: moduleVeryComplexV1,
		libs:   []string{libVeryComplexV1},
	},
}

func makeKind(i int) string {
	return fmt.Sprintf("foo%d", i)
}

const moduleSimple = `package foo

violation[{"msg": msg}] {
  input.review.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %%v", [input.parameters.foo])
}`

const moduleSimpleV1 = `package foo

violation contains {"msg": msg} if {
  input.review.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %%v", [input.parameters.foo])
}`

const moduleComplex = `package foo

identical(obj, review) {
  obj.metadata.namespace == review.object.metadata.namespace
  obj.metadata.name == review.object.metadata.name
}

violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  re_match("^(extensions|networking.k8s.io)$", input.review.kind.group)
  host := input.review.object.spec.rules[_].host
  other := data.inventory.namespace[ns][otherapiversion]["Ingress"][name]
  re_match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
  other.spec.rules[_].host == host
  not identical(other, input.review)
  msg := sprintf("Ingress host conflicts with an existing Ingress <%%v>", [host])
}`

const moduleComplexV1 = `package foo

identical(obj, review) if {
  obj.metadata.namespace == review.object.metadata.namespace
  obj.metadata.name == review.object.metadata.name
}

violation contains {"msg": msg} if {
  input.review.kind.kind == "Ingress"
  regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
  host := input.review.object.spec.rules[_].host
  other := data.inventory.namespace[ns][otherapiversion]["Ingress"][name]
  regex.match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
  other.spec.rules[_].host == host
  not identical(other, input.review)
  msg := sprintf("Ingress host conflicts with an existing Ingress <%%v>", [host])
}`

const libVeryComplex = `package lib.helpers

missing(obj, field) = true {
    not obj[field]
}

missing(obj, field) = true {
  obj[field] == ""
}

canonify_cpu(orig) = new {
  is_number(orig)
  new := orig * 1000
}

canonify_cpu(orig) = new {
  not is_number(orig)
  endswith(orig, "m")
  new := to_number(replace(orig, "m", ""))
}

canonify_cpu(orig) = new {
  not is_number(orig)
  not endswith(orig, "m")
  re_match("^[0-9]+$", orig)
  new := to_number(orig) * 1000
}

# 10 ** 21
mem_multiple("E") = 1000000000000000000000 { true }

# 10 ** 18
mem_multiple("P") = 1000000000000000000 { true }

# 10 ** 15
mem_multiple("T") = 1000000000000000 { true }

# 10 ** 12
mem_multiple("G") = 1000000000000 { true }

# 10 ** 9
mem_multiple("M") = 1000000000 { true }

# 10 ** 6
mem_multiple("k") = 1000000 { true }

# 10 ** 3
mem_multiple("") = 1000 { true }

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
mem_multiple("m") = 1 { true }

# 1000 * 2 ** 10
mem_multiple("Ki") = 1024000 { true }

# 1000 * 2 ** 20
mem_multiple("Mi") = 1048576000 { true }

# 1000 * 2 ** 30
mem_multiple("Gi") = 1073741824000 { true }

# 1000 * 2 ** 40
mem_multiple("Ti") = 1099511627776000 { true }

# 1000 * 2 ** 50
mem_multiple("Pi") = 1125899906842624000 { true }

# 1000 * 2 ** 60
mem_multiple("Ei") = 1152921504606846976000 { true }

get_suffix(mem) = suffix {
  not is_string(mem)
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  suffix := substring(mem, count(mem) - 1, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  suffix := substring(mem, count(mem) - 2, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  not substring(mem, count(mem) - 1, -1)
  not substring(mem, count(mem) - 2, -1)
  suffix := ""
}

canonify_mem(orig) = new {
  is_number(orig)
  new := orig * 1000
}

canonify_mem(orig) = new {
  not is_number(orig)
  suffix := get_suffix(orig)
  raw := replace(orig, suffix, "")
  new := to_number(raw) * mem_multiple(suffix)
}`

const libVeryComplexV1 = `
package lib.helpers

missing(obj, field) if {
	not obj[field]
}

missing(obj, field) if {
	obj[field] == ""
}

canonify_cpu(orig) := new if {
	is_number(orig)
	new := orig * 1000
}

canonify_cpu(orig) := new if {
	not is_number(orig)
	endswith(orig, "m")
	new := to_number(replace(orig, "m", ""))
}

canonify_cpu(orig) := new if {
	not is_number(orig)
	not endswith(orig, "m")
	regex.match("^[0-9]+$", orig)
	new := to_number(orig) * 1000
}

# 10 ** 21
mem_multiple("E") := 1000000000000000000000

# 10 ** 18
mem_multiple("P") := 1000000000000000000

# 10 ** 15
mem_multiple("T") := 1000000000000000

# 10 ** 12
mem_multiple("G") := 1000000000000

# 10 ** 9
mem_multiple("M") := 1000000000

# 10 ** 6
mem_multiple("k") := 1000000

# 10 ** 3
mem_multiple("") := 1000

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
mem_multiple("m") := 1

# 1000 * 2 ** 10
mem_multiple("Ki") := 1024000

# 1000 * 2 ** 20
mem_multiple("Mi") := 1048576000

# 1000 * 2 ** 30
mem_multiple("Gi") := 1073741824000

# 1000 * 2 ** 40
mem_multiple("Ti") := 1099511627776000

# 1000 * 2 ** 50
mem_multiple("Pi") := 1125899906842624000

# 1000 * 2 ** 60
mem_multiple("Ei") := 1152921504606846976000

get_suffix(mem) := suffix if {
	not is_string(mem)
	suffix := ""
}

get_suffix(mem) := suffix if {
	is_string(mem)
	suffix := substring(mem, count(mem) - 1, -1)
	mem_multiple(suffix)
}

get_suffix(mem) := suffix if {
	is_string(mem)
	suffix := substring(mem, count(mem) - 2, -1)
	mem_multiple(suffix)
}

get_suffix(mem) := suffix if {
	is_string(mem)
	not substring(mem, count(mem) - 1, -1)
	not substring(mem, count(mem) - 2, -1)
	suffix := ""
}

canonify_mem(orig) := new if {
	is_number(orig)
	new := orig * 1000
}

canonify_mem(orig) := new if {
	not is_number(orig)
	suffix := get_suffix(orig)
	raw := replace(orig, suffix, "")
	new := to_number(raw) * mem_multiple(suffix)
}
`

const moduleVeryComplex = `package k8scontainerlimits
import data.lib.helpers

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  cpu_orig := container.resources.limits.cpu
  not helpers.canonify_cpu(cpu_orig)
  msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  mem_orig := container.resources.limits.memory
  not helpers.canonify_mem(mem_orig)
  msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.resources
  msg := sprintf("container <%v> has no resource limits", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.resources.limits
  msg := sprintf("container <%v> has no resource limits", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  helpers.missing(container.resources.limits, "cpu")
  msg := sprintf("container <%v> has no cpu limit", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  helpers.missing(container.resources.limits, "memory")
  msg := sprintf("container <%v> has no memory limit", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  cpu_orig := container.resources.limits.cpu
  cpu := helpers.canonify_cpu(cpu_orig)
  max_cpu_orig := input.parameters.cpu
  max_cpu := helpers.canonify_cpu(max_cpu_orig)
  cpu > max_cpu
  msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  mem_orig := container.resources.limits.memory
  mem := helpers.canonify_mem(mem_orig)
  max_mem_orig := input.parameters.memory
  max_mem := helpers.canonify_mem(max_mem_orig)
  mem > max_mem
  msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
}

`

const moduleVeryComplexV1 = `
package k8scontainerlimits

import data.lib.helpers

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	cpu_orig := container.resources.limits.cpu
	not helpers.canonify_cpu(cpu_orig)
	msg := sprintf(
		"container <%v> cpu limit <%v> could not be parsed",
		[container.name, cpu_orig],
	)
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	mem_orig := container.resources.limits.memory
	not helpers.canonify_mem(mem_orig)
	msg := sprintf(
		"container <%v> memory limit <%v> could not be parsed",
		[container.name, mem_orig],
	)
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	not container.resources
	msg := sprintf("container <%v> has no resource limits", [container.name])
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	not container.resources.limits
	msg := sprintf("container <%v> has no resource limits", [container.name])
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	helpers.missing(container.resources.limits, "cpu")
	msg := sprintf("container <%v> has no cpu limit", [container.name])
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	helpers.missing(container.resources.limits, "memory")
	msg := sprintf("container <%v> has no memory limit", [container.name])
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	cpu_orig := container.resources.limits.cpu
	cpu := helpers.canonify_cpu(cpu_orig)
	max_cpu_orig := input.parameters.cpu
	max_cpu := helpers.canonify_cpu(max_cpu_orig)
	cpu > max_cpu
	msg := sprintf(
		"container <%v> cpu limit <%v> is higher than the maximum allowed of <%v>",
		[container.name, cpu_orig, max_cpu_orig],
	)
}

violation contains {"msg": msg} if {
	some container in input.review.object.spec.containers
	mem_orig := container.resources.limits.memory
	mem := helpers.canonify_mem(mem_orig)
	max_mem_orig := input.parameters.memory
	max_mem := helpers.canonify_mem(max_mem_orig)
	mem > max_mem
	msg := sprintf(
		"container <%v> memory limit <%v> is higher than the maximum allowed of <%v>",
		[container.name, mem_orig, max_mem_orig],
	)
}
`

func makeConstraintTemplate(i int, module string, libs ...string) *templates.ConstraintTemplate {
	kind := makeKind(i)
	ct := &templates.ConstraintTemplate{}
	ct.SetName(kind)
	ct.Spec.CRD.Spec.Names.Kind = kind
	ct.Spec.Targets = []templates.Target{{
		Target: handlertest.TargetName,
		Code: []templates.Code{
			{
				Engine: schema.Name,
				Source: &templates.Anything{
					Value: (&schema.Source{
						Rego: module,
						Libs: libs,
					}).ToUnstructured(),
				},
			},
		},
	}}

	return ct
}

func TestAddTemplate(t *testing.T) {
	for _, tc := range modules {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			c := clienttest.New(t)

			_, err := c.AddTemplate(ctx, makeConstraintTemplate(0, tc.module, tc.libs...))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
