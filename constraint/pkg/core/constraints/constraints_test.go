package constraints

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestSemanticEqual(t *testing.T) {
	testCases := []struct {
		name string
		c1   *unstructured.Unstructured
		c2   *unstructured.Unstructured
		want bool
	}{
		{
			name: "empty Constraints",
			c1:   &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			c2:   &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			want: true,
		},
		{
			name: "one empty Constraint",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "a",
				},
			},
			c2:   &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			want: false,
		},
		{
			name: "equal Constraints",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "a",
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "a",
				},
			},
			want: true,
		},
		{
			name: "unequal Constraints",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "a",
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "b",
				},
			},
			want: false,
		},
		{
			name: "equal Constraints map",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"a": "b"},
				},
			},
			want: true,
		},
		{
			name: "unequal Constraints",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"c": "d"},
				},
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SemanticEqual(tc.c1, tc.c2)
			if got != tc.want {
				t.Fatalf("got SemanticEqual(c1, c2) = %v, want %v", got, tc.want)
			}

			got2 := SemanticEqual(tc.c2, tc.c1)
			if got2 != tc.want {
				t.Fatalf("got SemanticEqual(c2, c1) = %v, want %v", got, tc.want)
			}
		})
	}
}
