package local

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkDriver_PutModule(b *testing.B) {
	for _, n := range []int{1, 2, 5, 10, 20, 50, 100, 200} {
		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				ctx := context.Background()
				d := New()
				b.StartTimer()

				for j := 0; j < n; j++ {
					name := fmt.Sprintf("foo-%d", j)
					err := d.PutModules(ctx, name, []string{makeModule("foo")})
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkDriver_Query(b *testing.B) {
	for _, n := range []int{1, 2, 5, 10, 20, 50, 100, 200} {
		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			ctx := context.Background()
			d := New()

			for j := 0; j < n; j++ {
				kind := fmt.Sprintf("foo%d", j)
				err := d.PutModules(ctx, kind, []string{makeModule(kind)})
				if err != nil {
					b.Fatal(err)
				}

				err = d.PutData(ctx, "", makeConstraint(kind))
				if err != nil {
					b.Fatal(err)
				}
			}

			obj := makeInput()

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := d.Query(ctx, obj)

				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
