package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest/cts"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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
			return cts.MakeConstraint(b, makeKind(tid), name, cts.WantData("bar"))
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
			return cts.MakeConstraint(b, makeKind(tid), name, cts.WantData("bar"))
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
			return cts.MakeConstraint(b, makeKind(tid), name,
				cts.WantData("bar"),
				cts.MatchNamespace("zab"))
		},
	}, {
		name: "autoreject",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name: "has-foo",
				Data: "foo",
			},
		},
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, makeKind(tid), name, cts.WantData("bar"))
		},
	}}

	for _, templates := range []int{1, 10, 100} {
		for _, constraints := range []int{1, 5, 10, 50, 100, 500, 1000} {
			if templates > constraints {
				continue
			}

			for _, tt := range tests {
				c := clienttest.New(b)

				for ts := 0; ts < templates; ts++ {
					ct := clienttest.TemplateCheckData()
					ct.Spec.CRD.Spec.Names.Kind = makeKind(ts)
					ct.Name = strings.ToLower(makeKind(ts))

					_, err := c.AddTemplate(ct)
					if err != nil {
						b.Fatal(err)
					}
				}

				ctx := context.Background()
				for cs := 0; cs < constraints; cs++ {
					// Approximately evenly distribute Constraints among Templates.
					tid := cs % templates
					cid := cs / templates

					name := fmt.Sprintf("wantbar-%d", cid)
					constraint := tt.makeConstraint(tid, name)

					_, err := c.AddConstraint(constraint)
					if err != nil {
						b.Fatal(err)
					}
				}

				b.Run(fmt.Sprintf("%d Constraints %d Templates %s", constraints, templates, tt.name), func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, err := c.Review(ctx, tt.review)
						if err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}
