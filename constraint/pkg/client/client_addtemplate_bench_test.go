package client_test

import (
	"context"
	"fmt"
	"sync"
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
}

func makeKind(i int) string {
	return fmt.Sprintf("foo%d", i)
}

const moduleSimple = `package foo

violation[{"msg": msg}] {
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

func BenchmarkClient_AddTemplate(b *testing.B) {
	for _, tc := range modules {
		b.Run(tc.name, func(b *testing.B) {
			for _, n := range []int{1, 2, 5, 10, 20, 50, 100, 200} {
				b.Run(fmt.Sprintf("%d Templates", n), func(b *testing.B) {
					ctx := context.Background()
					cts := make([]*templates.ConstraintTemplate, n)
					for i := range cts {
						cts[i] = makeConstraintTemplate(i, tc.module, tc.libs...)
					}

					for i := 0; i < b.N; i++ {
						b.StopTimer()

						c := clienttest.New(b)

						b.StartTimer()

						for _, ct := range cts {
							_, err := c.AddTemplate(ctx, ct)
							if err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		})
	}
}

// BenchmarkClient_AddTemplate_Parallel measures performance when adding N
// ConstraintTemplates to a client in parallel.
func BenchmarkClient_AddTemplate_Parallel(b *testing.B) {
	for _, tc := range modules {
		b.Run(tc.name, func(b *testing.B) {
			for _, n := range []int{1, 2, 5, 10, 20, 50, 100, 200} {
				b.Run(fmt.Sprintf("%d Templates", n), func(b *testing.B) {
					cts := make([]*templates.ConstraintTemplate, n)
					for i := range cts {
						cts[i] = makeConstraintTemplate(i, tc.module, tc.libs...)
					}
					b.ResetTimer()

					for i := 0; i < b.N; i++ {
						b.StopTimer()

						ctx := context.Background()
						c := clienttest.New(b)

						b.StartTimer()

						// wgChan is only written to once all Templates have been added successfully.
						wgChan := make(chan bool)
						// errChan records any errors which occurred while adding Templates.
						errChan := make(chan error)

						go func() {
							wg := sync.WaitGroup{}
							wg.Add(len(cts))

							// Add Templates in individual goroutines so that calls are as
							// simultaneous as reasonable..
							for _, ct := range cts {
								// Shadow ct to allow the variable to be safely passed in to the
								// goroutine.
								ct := ct
								go func() {
									_, err := c.AddTemplate(ctx, ct)
									if err != nil {
										// Notify errChan so we can stop the test.
										// Errors should never happen under these conditions.
										// We can't directly fail the benchmark from within a
										// goroutine.
										errChan <- err
									} else {
										// Only notify the WaitGroup on success to avoid falsely
										// reporting success.
										wg.Done()
									}
								}()
							}

							// Wait for all Templates to be added, and then notify the wait channel.
							wg.Wait()
							wgChan <- true
						}()

						// Wait for an error to be written to the error channel or the wgChan
						// to note that it has completed successfully.
						select {
						case err := <-errChan:
							b.Fatal(err)
						case <-wgChan:
						}
					}
				})
			}
		})
	}
}
