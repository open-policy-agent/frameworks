package client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
)

func BenchmarkClient_AddConstraint(b *testing.B) {
	ctx := context.Background()

	c := clienttest.New(b)

	_, err := c.AddTemplate(clienttest.TemplateCheckData())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("foo-%d", i)
		constraint := cts.MakeConstraint(b, clienttest.KindCheckData, name, cts.WantData("bar"))

		_, err = c.AddConstraint(ctx, constraint)
		if err != nil {
			b.Fatal(err)
		}
	}
}
