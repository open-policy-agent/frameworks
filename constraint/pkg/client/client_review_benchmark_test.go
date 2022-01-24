package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/clienttest"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

var nConstraints = []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}

func kind(tid int) string {
	return fmt.Sprintf("%s-%d", clienttest.KindCheckData, tid)
}

func BenchmarkClient_Review_AllSuccess(b *testing.B) {
	tests := []struct{
		name string
		review handlertest.Review
	} {{
		name: "success",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name: "has-bar",
				Data: "bar",
			},
		},
	}, {
		name: "fail",
		review: handlertest.Review{
			Object: handlertest.Object{
				Name: "has-foo",
				Data: "foo",
			},
		},
	}}

	for _, templates := range nTemplates {
		for _, constraints := range nConstraints {
			if templates > constraints {
				continue
			}

			c := clienttest.New(b)

			for ts := 0; ts < templates; ts++ {
				ct := clienttest.TemplateCheckData()
				ct.Spec.CRD.Spec.Names.Kind = kind(ts)
				ct.Name = strings.ToLower(kind(ts))

				_, err := c.AddTemplate(ct)
				if err != nil {
					b.Fatal(err)
				}
			}

			ctx := context.Background()
			for cs := 0; cs < constraints; cs++ {
				// Approximately evnely distribute Constraints among Templates.
				tid := cs % templates
				cid := cs / templates

				name := fmt.Sprintf("wantbar-%d", cid)
				constraint := clienttest.MakeConstraint(b, kind(tid), name, clienttest.WantData("bar"))

				_, err := c.AddConstraint(ctx, constraint)
				if err != nil {
					b.Fatal(err)
				}
			}

			for _, tt := range tests {
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
