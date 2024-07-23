package constraints

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// WebhookEnforcementPoint is the enforcement point for admission.
	WebhookEnforcementPoint = "validation.gatekeeper.sh"

	// AuditEnforcementPoint is the enforcement point for audit.
	AuditEnforcementPoint = "audit.gatekeeper.sh"

	// GatorEnforcementPoint is the enforcement point for gator cli.
	GatorEnforcementPoint = "gator.gatekeeper.sh"
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
			name: "Actions for selective enforcement point with case sensitive input",
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
										"name": "Validation.Gatekeeper.Sh",
									},
								},
								"action": "Warn",
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
		{
			name: "wildcard enforcement point in scoped enforcement action, get actions for all enforcement points",
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
										"name": AllEnforcementPoints,
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
				AllEnforcementPoints: {
					"deny": true,
				},
			},
			eps: []string{AllEnforcementPoints},
		},
		{
			name: "wildcard enforcement point in scoped enforcement action, get actions for two enforcement points",
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
										"name": AllEnforcementPoints,
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
			},
			eps: []string{WebhookEnforcementPoint, AuditEnforcementPoint},
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
