package client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// BenchmarkClient_Review runs queries in parallel to determine the maximum
// query throughput for a given setup.
//
// To measure single-threaded performance, set GOMAXPROCS to 1.
func BenchmarkClient_Review(b *testing.B) {
	tests := []struct {
		name           string
		review         handlertest.Review
		makeConstraint func(tid int, name string) *unstructured.Unstructured
	}{{
		name: "success",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name: "has-bar",
				Data: "bar",
			},
		},
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, clienttest.KindCheckDataNumbered(tid), name, cts.WantData("bar"))
		},
	}, {
		name: "fail",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name: "has-foo",
				Data: "foo",
			},
		},
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, clienttest.KindCheckDataNumbered(tid), name, cts.WantData("bar"))
		},
	}, {
		name: "filtered out",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name:      "has-foo",
				Namespace: "qux",
				Data:      "foo",
			},
		},
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, clienttest.KindCheckDataNumbered(tid), name,
				cts.WantData("bar"),
				cts.MatchNamespace("zab"))
		},
	}, {
		name: "autoreject",
		review: handlertest.Review{
			Object: handlertest.Object{
				Namespace: "aaa",
				Name:      "has-foo",
				Data:      "foo",
			},
		},
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, clienttest.KindCheckDataNumbered(tid), name,
				cts.WantData("bar"), cts.MatchNamespace("aaa"))
		},
	}}

	for _, templates := range []int{1, 10, 100} {
		for _, constraints := range []int{1, 5, 10, 50, 100, 500, 1000} {
			if templates > constraints {
				continue
			}

			for _, tt := range tests {
				c := clienttest.New(b)

				ctx := context.Background()
				for ts := 0; ts < templates; ts++ {
					ct := clienttest.TemplateCheckDataNumbered(ts)

					_, err := c.AddTemplate(ctx, ct)
					if err != nil {
						b.Fatal(err)
					}
				}

				for cs := 0; cs < constraints; cs++ {
					// Approximately evenly distribute Constraints among Templates.
					tid := cs % templates
					cid := cs / templates

					name := fmt.Sprintf("wantbar-%d", cid)
					constraint := tt.makeConstraint(tid, name)

					_, err := c.AddConstraint(ctx, constraint)
					if err != nil {
						b.Fatal(err)
					}
				}

				b.Run(fmt.Sprintf("%d Constraints %d Templates %s", constraints, templates, tt.name), func(b *testing.B) {
					b.ResetTimer()
					// Run Review queries in parallel.
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							_, err := c.Review(ctx, tt.review, "")
							if err != nil {
								b.Fatal(err)
							}
						}
					})
				})
			}
		}
	}
}
