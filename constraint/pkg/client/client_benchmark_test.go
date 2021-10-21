package client

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func makeKind(i int) string {
	return fmt.Sprintf("foo%d", i)
}

func makeModule(i int) string {
	kind := makeKind(i)
	return fmt.Sprintf(`package %s

violation[msg] {
  input.review.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %%v", [input.parameters.foo])
}`, kind)
}

func makeConstraintTemplate(i int) *templates.ConstraintTemplate {
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

func makeConstraint(i int, j int) *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{}
	constraint.SetKind(makeKind(i))
	constraint.SetAPIVersion("constraints.gatekeeper.sh/v1beta1")
	constraint.SetName(fmt.Sprintf("foo-%d", j))
	err := unstructured.SetNestedField(constraint.Object, "qux", "foo")
	if err != nil {
		panic(err)
	}

	return constraint
}

func makeObject() *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"foo": "qux",
		},
	}
}

func TestClient(t *testing.T) {
	d := local.New()

	b, err := NewBackend(Driver(d))
	if err != nil {
		t.Fatal(err)
	}

	c, err := b.NewClient(Targets(&handler{}))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	for i := 0; i < 20; i++ {
		ct := makeConstraintTemplate(i)
		_, err = c.AddTemplate(ctx, ct)
		if err != nil {
			t.Fatal(err)
		}

		constraint := makeConstraint(i, 0)
		_, err = c.AddConstraint(ctx, constraint)
		if err != nil {
			t.Fatal(err)
		}

		constraint = makeConstraint(i, 1)
		_, err = c.AddConstraint(ctx, constraint)
		if err != nil {
			t.Fatal(err)
		}
	}


	obj := makeObject()
	rsps, err := c.Review(ctx, obj)
	if err != nil {
		t.Fatal(err)
	}

	results := rsps.Results()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Msg < results[j].Msg
	})

	if len(results) != 40 {
		t.Errorf("got %d results, want %d", len(results), 20)
	}
}

var nTemplates = []int{1, 2, 5, 10, 20, 50, 100, 200}
var nConstraints = []int{1, 2, 5, 10}

func BenchmarkClient_AddTemplate(b *testing.B) {
	ctx := context.Background()
	targets := Targets(&handler{})

	for _, n := range nTemplates {
		cts := make([]*templates.ConstraintTemplate, n)
		for i := range cts {
			cts[i] = makeConstraintTemplate(i)
		}

		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
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
					_, _ = c.AddTemplate(ctx, ct)
				}
			}
		})
	}
}

func BenchmarkClient_Query(b *testing.B) {
	ctx := context.Background()
	targets := Targets(&handler{})

	for _, n := range nTemplates {
		for _, nc := range nConstraints {
			b.Run(fmt.Sprintf("%d templates %d constraints each", n, nc), func(b *testing.B) {
				d := local.New()

				backend, err := NewBackend(Driver(d))
				if err != nil {
					b.Fatal(err)
				}

				c, err := backend.NewClient(targets)
				if err != nil {
					b.Fatal(err)
				}

				for i := 0; i < n; i++ {
					_, err = c.AddTemplate(ctx, makeConstraintTemplate(i))
					if err != nil {
						b.Fatal(err)
					}

					for j := 0; j < nc; j++ {
						_, err = c.AddConstraint(ctx, makeConstraint(i, j))
						if err != nil {
							b.Fatal(err)
						}
					}

					if i%10 < 0 {
						_, err = c.AddConstraint(ctx, makeConstraint(i, nc))
						if err != nil {
							b.Fatal(err)
						}
					}
				}

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					_, err := c.Review(ctx, makeObject())
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
