package constraints

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGetEnforcementActionsForEP(t *testing.T) {
	tests := []struct {
		name       string
		constraint *unstructured.Unstructured
		eps        []string
		expected   map[string]map[string]bool
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
										"name": AuditEnforcementPoint,
									},
									map[string]interface{}{
										"name": WebhookEnforcementPoint,
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
			expected: map[string]map[string]bool{
				AuditEnforcementPoint: {
					"warn": true,
					"deny": true,
				},
				WebhookEnforcementPoint: {
					"warn": true,
					"deny": true,
				},
				GatorEnforcementPoint: {
					"deny": true,
				},
			},
			eps: []string{AuditEnforcementPoint, WebhookEnforcementPoint, GatorEnforcementPoint},
		},
		{
			name: "Actions for selective enforcement point",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"scopedEnforcementActions": []interface{}{
							map[string]interface{}{
								"enforcementPoints": []interface{}{
									map[string]interface{}{
										"name": AuditEnforcementPoint,
									},
									map[string]interface{}{
										"name": WebhookEnforcementPoint,
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
			expected: map[string]map[string]bool{
				WebhookEnforcementPoint: {
					"warn": true,
					"deny": true,
				},
				GatorEnforcementPoint: {
					"deny": true,
				},
			},
			eps: []string{WebhookEnforcementPoint, GatorEnforcementPoint},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := GetEnforcementActionsForEP(tt.constraint, tt.eps)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !reflect.DeepEqual(actions, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, actions)
			}
		})
	}
}
