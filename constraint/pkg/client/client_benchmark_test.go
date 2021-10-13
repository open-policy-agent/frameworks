package client

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func newDenyAllConstraintTemplate(templateID int) *templates.ConstraintTemplate {
	name := fmt.Sprintf("denyall%d", templateID)
	rego := fmt.Sprintf(`package foo%d
violation[{"msg": "DENIED %d", "details": {}}] {
	"always" == "always"
}`, templateID, templateID)

	return newConstraintTemplate(name, rego)
}

func newDenyAllConstraint(templateID, constraintID int) *unstructured.Unstructured {
	kind := fmt.Sprintf("denyall%d", templateID)
	name := fmt.Sprintf("foo-%d", constraintID)
	return newConstraint(kind, name, nil, nil)
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

	ct := newDenyAllConstraintTemplate(0)
	_, err = c.AddTemplate(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}

	constraint := newDenyAllConstraint(0, 0)
	_, err = c.AddConstraint(ctx, constraint)
	if err != nil {
		t.Fatal(err)
	}

	ct = newDenyAllConstraintTemplate(1)
	_, err = c.AddTemplate(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}

	constraint = newDenyAllConstraint(1, 0)
	_, err = c.AddConstraint(ctx, constraint)
	if err != nil {
		t.Fatal(err)
	}

	rsps, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: ""})
	if err != nil {
		t.Fatal(err)
	}

	results := rsps.Results()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Msg < results[j].Msg
	})

	wantResults := []*types.Result{{
		Msg:               "DENIED 0",
		Metadata:          map[string]interface{}{"details": map[string]interface{}{}},
		EnforcementAction: "deny",
	}, {
		Msg:               "DENIED 1",
		Metadata:          map[string]interface{}{"details": map[string]interface{}{}},
		EnforcementAction: "deny",
	}}

	if diff := cmp.Diff(wantResults, results, cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(types.Result{}, "Constraint", "Review", "Resource")); diff != "" {
		t.Error(diff)
	}

	t.Fail()
}

func TestClient2(t *testing.T) {
	ctx := context.Background()
	targets := Targets(&handler{})

	for _, n := range nTemplates {
		d := local.New()

		backend, err := NewBackend(Driver(d))
		if err != nil {
			t.Fatal(err)
		}

		c, err := backend.NewClient(targets)
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < n; i++ {
			_, err = c.AddTemplate(ctx, newDenyAllConstraintTemplate(i))
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, newDenyAllConstraint(i, 0))
			if err != nil {
				t.Fatal(err)
			}
		}

		t.Run(fmt.Sprintf("%d templates", n), func(t *testing.T) {
			_, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "denyall0"})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

var nTemplates = []int{1, 2, 5, 10, 20, 50, 100, 200}

func BenchmarkClient_AddTemplate(b *testing.B) {
	ctx := context.Background()
	targets := Targets(&handler{})

	for _, n := range nTemplates {
		cts := make([]*templates.ConstraintTemplate, n)
		for i := range cts {
			cts[i] = newDenyAllConstraintTemplate(i)
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
			_, err = c.AddTemplate(ctx, newDenyAllConstraintTemplate(i))
			if err != nil {
				b.Fatal(err)
			}

			_, err = c.AddConstraint(ctx, newDenyAllConstraint(i, 0))
			if err != nil {
				b.Fatal(err)
			}
		}

		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := c.Review(ctx, targetData{Name: "Sara", ForConstraint: "denyall0"})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
