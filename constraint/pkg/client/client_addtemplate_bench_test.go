package client_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

var modules = []struct {
	name       string
	makeModule func(i int) string
}{{
	name:       "Simple",
	makeModule: makeModuleSimple,
}, {
	name:       "Complex",
	makeModule: makeModuleComplex,
}}

func makeKind(i int) string {
	return fmt.Sprintf("foo%d", i)
}

func makeModuleSimple(i int) string {
	kind := makeKind(i)
	return fmt.Sprintf(`package %s
violation[{"msg": msg}] {
  input.review.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %%v", [input.parameters.foo])
}`, kind)
}

func makeModuleComplex(i int) string {
	kind := makeKind(i)
	return fmt.Sprintf(`package %s

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
}`, kind)
}

func makeConstraintTemplate(i int, makeModule func(i int) string) *templates.ConstraintTemplate {
	kind := makeKind(i)
	ct := &templates.ConstraintTemplate{}
	ct.SetName(kind)
	ct.Spec.CRD.Spec.Names.Kind = kind
	ct.Spec.Targets = []templates.Target{{
		Target: "test.target",
		Rego:   makeModule(i),
	}}

	return ct
}

func BenchmarkClient_AddTemplate(b *testing.B) {
	for _, tc := range modules {
		b.Run(tc.name, func(b *testing.B) {
			for _, n := range []int{1, 2, 5, 10, 20, 50, 100, 200} {
				b.Run(fmt.Sprintf("%d Templates", n), func(b *testing.B) {
					cts := make([]*templates.ConstraintTemplate, n)
					for i := range cts {
						cts[i] = makeConstraintTemplate(i, tc.makeModule)
					}

					for i := 0; i < b.N; i++ {
						b.StopTimer()

						c := clienttest.New(b)

						b.StartTimer()

						for _, ct := range cts {
							_, err := c.AddTemplate(ct)
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
						cts[i] = makeConstraintTemplate(i, tc.makeModule)
					}

					for i := 0; i < b.N; i++ {
						b.StopTimer()

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
									_, err := c.AddTemplate(ct)
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
