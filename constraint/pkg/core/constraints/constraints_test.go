package constraints

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestSemanticEqualWithLabelsAndAnnotations(t *testing.T) {
	testCases := []struct {
		name string
		c1   *unstructured.Unstructured
		c2   *unstructured.Unstructured
		want bool
	}{
		{
			name: "nil Constraints",
			c1:   nil,
			c2:   nil,
			want: true,
		},
		{
			name: "nil and non-nil Constraints",
			c1:   nil,
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			want: false,
		},
		{
			name: "empty Constraints",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			want: true,
		},
		{
			name: "nil objects",
			c1: &unstructured.Unstructured{
				Object: nil,
			},
			c2: &unstructured.Unstructured{
				Object: nil,
			},
			want: true,
		},
		{
			name: "nil and non-nil Object",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			c2: &unstructured.Unstructured{
				Object: nil,
			},
			want: false,
		},
		{
			name: "one empty Constraint",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": "a",
				},
			},
			c2: &unstructured.Unstructured{
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
		{
			name: "equal labels",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"labels": map[string]interface{}{"select": "yes"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"labels": map[string]interface{}{"select": "yes"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: true,
		},
		{
			name: "different labels",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"labels": map[string]interface{}{"select": "yes"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"labels": map[string]interface{}{"select": "no"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: false,
		},
		{
			name: "equal annotations",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: true,
		},
		{
			name: "equal annotations, keys in different order",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit1": "enabled1", "audit2": "enabled2"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit2": "enabled2", "audit1": "enabled1"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: true,
		},
		{
			name: "different annotation values",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit": "disabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: false,
		},
		{
			name: "different annotation keys",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit2": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit1": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			want: false,
		},
		{
			name: "one has annotations, other doesn't",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{"annotations": map[string]interface{}{"audit": "enabled"}},
					"spec":     map[string]interface{}{"a": "b"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"a": "b"},
				},
			},
			want: false,
		},
		{
			name: "equal labels and annotations",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod", "team": "security"},
						"annotations": map[string]interface{}{"audit": "enabled", "export": "true"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod", "team": "security"},
						"annotations": map[string]interface{}{"audit": "enabled", "export": "true"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			want: true,
		},
		{
			name: "different labels, same annotations",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod"},
						"annotations": map[string]interface{}{"audit": "enabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "staging"},
						"annotations": map[string]interface{}{"audit": "enabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			want: false,
		},
		{
			name: "same labels, different annotations",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod"},
						"annotations": map[string]interface{}{"audit": "enabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod"},
						"annotations": map[string]interface{}{"audit": "disabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			want: false,
		},
		{
			name: "nil labels, equal annotations",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"annotations": map[string]interface{}{"export": "true"},
					},
					"spec": map[string]interface{}{"rule": "allow"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"annotations": map[string]interface{}{"export": "true"},
					},
					"spec": map[string]interface{}{"rule": "allow"},
				},
			},
			want: true,
		},
		{
			name: "nil annotations, equal labels",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{"team": "security"},
					},
					"spec": map[string]interface{}{"rule": "allow"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{"team": "security"},
					},
					"spec": map[string]interface{}{"rule": "allow"},
				},
			},
			want: true,
		},
		{
			name: "ignores status field",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod"},
						"annotations": map[string]interface{}{"audit": "enabled"},
					},
					"spec":   map[string]interface{}{"rule": "deny-all"},
					"status": map[string]interface{}{"violations": 5},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels":      map[string]interface{}{"env": "prod"},
						"annotations": map[string]interface{}{"audit": "enabled"},
					},
					"spec":   map[string]interface{}{"rule": "deny-all"},
					"status": map[string]interface{}{"violations": 10},
				},
			},
			want: true,
		},
		{
			name: "ignores other metadata fields",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":            "test-constraint-1",
						"namespace":       "default",
						"resourceVersion": "123",
						"uid":             "abc-123",
						"labels":          map[string]interface{}{"env": "prod"},
						"annotations":     map[string]interface{}{"audit": "enabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"name":            "test-constraint-2",
						"namespace":       "kube-system",
						"resourceVersion": "456",
						"uid":             "def-456",
						"labels":          map[string]interface{}{"env": "prod"},
						"annotations":     map[string]interface{}{"audit": "enabled"},
					},
					"spec": map[string]interface{}{"rule": "deny-all"},
				},
			},
			want: true,
		},
		{
			name: "empty labels and annotations are treated as nil",
			c1: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{},
					"spec":     map[string]interface{}{"rule": "allow"},
				},
			},
			c2: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{"rule": "allow"},
				},
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SemanticEqualWithLabelsAndAnnotations(tc.c1, tc.c2)
			if got != tc.want {
				t.Fatalf("got SemanticEqualWithLabelsAndAnnotations(c1, c2) = %v, want %v", got, tc.want)
			}

			got2 := SemanticEqualWithLabelsAndAnnotations(tc.c2, tc.c1)
			if got2 != tc.want {
				t.Fatalf("got SemanticEqualWithLabelsAndAnnotations(c2, c1) = %v, want %v", got2, tc.want)
			}
		})
	}
}
