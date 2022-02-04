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

func BenchmarkClient_Audit(b *testing.B) {
	tests := []struct {
		name           string
		makeConstraint func(tid int, name string) *unstructured.Unstructured
		makeObject     func(oid int) *handlertest.Object
	}{{
		name: "success",
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, makeKind(tid), name, cts.WantData("bar"))
		},
		makeObject: func(oid int) *handlertest.Object {
			name := fmt.Sprintf("has-foo-%d", oid)
			return &handlertest.Object{
				Name: name,
				Data: "foo",
			}
		},
	}, {
		name: "fail",
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, makeKind(tid), name, cts.WantData("bar"))
		},
		makeObject: func(oid int) *handlertest.Object {
			name := fmt.Sprintf("has-foo-%d", oid)
			return &handlertest.Object{
				Name: name,
				Data: "foo",
			}
		},
	}, {
		name: "filtered out",
		makeConstraint: func(tid int, name string) *unstructured.Unstructured {
			return cts.MakeConstraint(b, makeKind(tid), name,
				cts.WantData("bar"),
				cts.MatchNamespace("zab"))
		},
		makeObject: func(oid int) *handlertest.Object {
			name := fmt.Sprintf("has-foo-%d", oid)
			return &handlertest.Object{
				Name:      name,
				Namespace: "qux",
				Data:      "foo",
			}
		},
	}}

	for _, templates := range []int{1, 10, 100} {
		for _, constraints := range []int{1, 5, 10, 50, 100} {
			for _, objects := range []int{0, 1, 10, 100} {
				for _, tt := range tests {
					if templates > constraints {
						continue
					}

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

						_, err := c.AddConstraint(ctx, constraint)
						if err != nil {
							b.Fatal(err)
						}
					}

					for oid := 0; oid < objects; oid++ {
						obj := tt.makeObject(oid)
						_, err := c.AddData(ctx, obj)
						if err != nil {
							b.Fatal(err)
						}
					}

					b.Run(fmt.Sprintf("%d Object %d Constraints %d Templates %s", objects, constraints, templates, tt.name), func(b *testing.B) {
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							_, err := c.Audit(ctx)
							if err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}
