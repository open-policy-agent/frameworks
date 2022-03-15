package client_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
)

func BenchmarkClient_AddConstraint(b *testing.B) {
	ctx := context.Background()
	c := clienttest.New(b)

	for i := 0; i < 10; i++ {
		_, err := c.AddTemplate(ctx, clienttest.TemplateCheckDataNumbered(i))
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		kind := clienttest.KindCheckDataNumbered(int(i % 10))
		name := fmt.Sprintf("foo-%d", i)
		constraint := cts.MakeConstraint(b, kind, name, cts.WantData("bar"))

		_, err := c.AddConstraint(ctx, constraint)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClient_AddConstraint_Parallel measures the performance difference
// gained by adding Constraints in parallel.
//
// Run with --race to ensure locking is correct for concurrent calls to
// AddConstraint.
func BenchmarkClient_AddConstraint_Parallel(b *testing.B) {
	ctx := context.Background()
	c := clienttest.New(b)

	nTemplates := []int{1, 10}

	for _, n := range nTemplates {
		b.Run(fmt.Sprintf("%d-Templates", n), func(b *testing.B) {
			// Distribute Constraints randomly across Templates to allow for parallel
			// modifications.
			for i := 0; i < n; i++ {
				_, err := c.AddTemplate(ctx, clienttest.TemplateCheckDataNumbered(i))
				if err != nil {
					b.Fatal(err)
				}
			}

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					// Create a reasonably unique identifier for use in testing.
					// While collisions are possible, their impact on performance for this
					// benchmark is not measurable until many billions of Constraints have
					// been added.
					//
					// This is faster (and more reliable at generating distinct values) than
					// using time.Now().
					// Measured faster than using atomic.AddInt64().
					i := rand.Int63() //nolint:gosec

					ctx := context.Background()
					kind := clienttest.KindCheckDataNumbered(int(i) % n)
					name := fmt.Sprintf("foo-%d", i)
					constraint := cts.MakeConstraint(b, kind, name, cts.WantData("bar"))

					_, err := c.AddConstraint(ctx, constraint)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
