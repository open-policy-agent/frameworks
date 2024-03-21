package constraints

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetEnforcementActionsForEP(t *testing.T) {
	tests := []struct {
		name       string
		constraint *unstructured.Unstructured
		ep         string
		expected   []string
		err        error
	}{
		{
			name: "wildcard enforcement point",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"scopedEnforcementActions": []interface{}{
							map[string]interface{}{
								"enforcementPoints": []interface{}{
									map[string]interface{}{
										"name": "ep1",
									},
									map[string]interface{}{
										"name": "ep2",
									},
								},
								"action": "warn",
							},
							map[string]interface{}{
								"enforcementPoints": []interface{}{
									map[string]interface{}{
										"name": "*",
									},
								},
								"action": "deny",
							},
						},
					},
				},
			},
			ep:       "ep2",
			expected: []string{"deny", "warn"},
		},
		{
			name: "enforcement point not found",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"scopedEnforcementActions": []interface{}{
							map[string]interface{}{
								"enforcementPoints": []interface{}{
									map[string]interface{}{
										"name": "ep1",
									},
								},
								"action": "warn",
							},
							map[string]interface{}{
								"enforcementPoints": []interface{}{
									map[string]interface{}{
										"name": "ep2",
									},
								},
								"action": "deny",
							},
						},
					},
				},
			},
			ep:       "ep3",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := GetEnforcementActionsForEP(tt.constraint, tt.ep)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			l := 0
			for _, action := range actions {
				for _, expected := range tt.expected {
					if action == expected {
						l++
						break
					}
				}
			}
			if l != len(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, actions)
			}
		})
	}
}
