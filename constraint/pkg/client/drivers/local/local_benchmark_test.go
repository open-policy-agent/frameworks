package local

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

var numTemplates = []int{1, 2, 5, 10, 20, 50, 100, 200}

func makeModule(i int) string {
	return fmt.Sprintf(`package foobar%d

violation[msg] {
  input.foo == "bar"
  msg := "input.foo is bar %d"
}`, i, i)
}

func BenchmarkDriver_PutModules(b *testing.B) {
	for _, n := range numTemplates {
		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			ctx := context.Background()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				d := New()
				b.StartTimer()

				for j := 0; j < n; j++ {
					name := fmt.Sprintf("foo-%d", j)
					err := d.PutModules(ctx, name, []string{makeModule(i)})
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func TestDriver_Query(t *testing.T) {
	t.Skip()

	ctx := context.Background()
	d := New()

	err := d.PutModules(ctx, "fooisbar", []string{Module})
	if err != nil {
		t.Fatal(err)
	}

	rsps, err := d.Query(ctx, "hooks", map[string]string{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}

	jsn, _ := json.MarshalIndent(rsps, "", "  ")
	t.Fatal(string(jsn))
}

func BenchmarkDriver_Query(b *testing.B) {
	for _, n := range numTemplates {
		b.Run(fmt.Sprintf("%d templates", n), func(b *testing.B) {
			ctx := context.Background()
			d := New()
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("foo-%d", i)
				err := d.PutModule(ctx, name, makeModule(i))
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := d.Query(ctx, "foo", map[string]string{"foo": "bar"})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
