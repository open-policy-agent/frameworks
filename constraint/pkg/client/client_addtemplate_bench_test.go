package client

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

var (
	nTemplates = []int{1, 2, 5, 10, 20, 50, 100, 200}

	modules = []struct {
		name       string
		makeModule func(i int) string
	}{{
		name:       "Simple",
		makeModule: makeModuleSimple,
	}, {
		name:       "Complex",
		makeModule: makeModuleComplex,
	}}
)

func makeKind(i int) string {
	return fmt.Sprintf("foo%d", i)
}

func makeModuleSimple(i int) string {
	kind := makeKind(i)
	return fmt.Sprintf(`package %s
violation[msg] {
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
			for _, n := range nTemplates {
				b.Run(fmt.Sprintf("%d Templates", n), func(b *testing.B) {
					cts := make([]*templates.ConstraintTemplate, n)
					for i := range cts {
						cts[i] = makeConstraintTemplate(i, tc.makeModule)
					}

					for i := 0; i < b.N; i++ {
						b.StopTimer()
						targets := Targets(&handler{})

						d := local.New()

						backend, err := NewBackend(Driver(d))
						if err != nil {
							b.Fatal(err)
						}

						c, err := backend.NewClient(targets)
						if err != nil {
							b.Fatal(err)
						}

						b.StartTimer()

						for _, ct := range cts {
							_, _ = c.AddTemplate(ct)
						}
					}
				})
			}
		})
	}
}
