package local

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	Module string = `
package foo

violation[msg] {
  input.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %v", [input.parameters.foo])
}
`
)

func makeModule(kind string) string {
	return fmt.Sprintf(`package %s

violation[msg] {
  input.object.foo == input.parameters.foo
  msg := sprintf("input.foo is %%v", [input.parameters.foo])
}`, kind)
}

func makeConstraint(kind string) *unstructured.Unstructured {
	constraint := &unstructured.Unstructured{}
	constraint.SetKind(kind)
	err := unstructured.SetNestedField(constraint.Object, "qux", "foo")
	if err != nil {
		panic(err)
	}

	return constraint
}

func TestDriver_Query(t *testing.T) {
	d := New()

	kind := "foo"

	ctx := context.Background()
	err := d.PutModules(ctx, kind, []string{makeModule(kind)})
	if err != nil {
		t.Fatal(err)
	}

	constraint := makeConstraint(kind)

	err = d.PutData(ctx, "", constraint)
	if err != nil {
		t.Fatal(err)
	}

	results, err := d.Query(ctx, map[string]interface{}{
		"object": map[string]interface{}{
			"foo": "qux",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	jsn, _ := json.MarshalIndent(results, "", "  ")
	t.Fatal(string(jsn))
}
