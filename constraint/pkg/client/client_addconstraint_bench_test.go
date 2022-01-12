package client

import (
	"context"
	"strconv"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func makeConstraint(i int, ct *templates.ConstraintTemplate) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetName(strconv.Itoa(i))
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "constraints.gatekeeper.sh",
		Version: "v1beta1",
		Kind:    ct.Spec.CRD.Spec.Names.Kind,
	})

	return u
}

func BenchmarkClient_AddConstraint(b *testing.B) {
	ctx := context.Background()

	ct := makeConstraintTemplate(0, makeModuleSimple)

	d := local.New()
	backend, err := NewBackend(Driver(d))
	if err != nil {
		b.Fatal(err)
	}

	targets := Targets(&handler{})

	c, err := backend.NewClient(targets)
	if err != nil {
		b.Fatal(err)
	}

	_, err = c.AddTemplate(ct)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		constraint := makeConstraint(i, ct)

		_, err = c.AddConstraint(ctx, constraint)
		if err != nil {
			b.Fatal(err)
		}
	}
}
