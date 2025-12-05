package client

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestTemplateClient_MatchesOperation(t *testing.T) {
	tests := []struct {
		name        string
		targets     []templates.Target
		operation   string
		expected    bool
		description string
	}{
		{
			name:        "no targets - returns true for backward compatibility",
			targets:     []templates.Target{},
			operation:   "CREATE",
			expected:    true,
			description: "when no targets are defined, should return true for backward compatibility",
		},
		{
			name: "multiple targets - returns true for backward compatibility",
			targets: []templates.Target{
				{Target: "target1"},
				{Target: "target2"},
			},
			operation:   "CREATE",
			expected:    true,
			description: "when multiple targets are defined, should return true for backward compatibility",
		},
		{
			name: "single target with no operations - allows all operations",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{},
				},
			},
			operation:   "CREATE",
			expected:    true,
			description: "when no operations are specified, should allow all operations",
		},
		{
			name: "single target with CREATE operation - matches CREATE",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				},
			},
			operation:   "CREATE",
			expected:    true,
			description: "should match when operation is explicitly listed",
		},
		{
			name: "single target with CREATE operation - does not match UPDATE",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				},
			},
			operation:   "UPDATE",
			expected:    false,
			description: "should not match when operation is not listed",
		},
		{
			name: "single target with multiple operations - matches CREATE",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				},
			},
			operation:   "CREATE",
			expected:    true,
			description: "should match when operation is one of multiple listed operations",
		},
		{
			name: "single target with multiple operations - does not match DELETE",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
				},
			},
			operation:   "DELETE",
			expected:    false,
			description: "should not match when operation is not in the list",
		},
		{
			name: "single target with wildcard operation - matches DELETE",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				},
			},
			operation:   "DELETE",
			expected:    true,
			description: "should match any operation when wildcard (*) is specified",
		},
		{
			name: "single target with mixed operations including wildcard",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.OperationAll},
				},
			},
			operation:   "DELETE",
			expected:    true,
			description: "should match when wildcard is present even with other specific operations",
		},
		{
			name: "empty operation string",
			targets: []templates.Target{
				{
					Target:     "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				},
			},
			operation:   "",
			expected:    false,
			description: "should not match empty operation string",
		},
		{
			name: "all standard operations",
			targets: []templates.Target{
				{
					Target: "admission.k8s.gatekeeper.sh",
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
						admissionregistrationv1.Delete,
						admissionregistrationv1.Connect,
					},
				},
			},
			operation:   "UPDATE",
			expected:    true,
			description: "should match when operation is in comprehensive list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &templateClient{
				template: &templates.ConstraintTemplate{
					Spec: templates.ConstraintTemplateSpec{
						Targets: tt.targets,
					},
				},
			}

			result := tc.MatchesOperation(tt.operation)

			if result != tt.expected {
				t.Errorf("MatchesOperation(%q) = %v, expected %v\nDescription: %s",
					tt.operation, result, tt.expected, tt.description)
			}
		})
	}
}

func TestTemplateClient_MatchesOperation_EdgeCases(t *testing.T) {
	t.Run("nil template", func(t *testing.T) {
		tc := &templateClient{
			template: nil,
		}

		// This should panic or handle gracefully
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Function panicked as expected when template is nil: %v", r)
			}
		}()

		// If it doesn't panic, it should return false or handle gracefully
		result := tc.MatchesOperation("CREATE")
		t.Logf("Result with nil template: %v", result)
	})

	t.Run("nil template spec", func(t *testing.T) {
		tc := &templateClient{
			template: &templates.ConstraintTemplate{},
		}

		// Should handle gracefully when spec is not initialized
		result := tc.MatchesOperation("CREATE")
		expected := true // Should return true for backward compatibility when no targets
		if result != expected {
			t.Errorf("MatchesOperation with nil spec = %v, expected %v", result, expected)
		}
	})
}

func TestTemplateClient_MatchesOperation_BackwardCompatibility(t *testing.T) {
	tests := []struct {
		name        string
		targetCount int
		operation   string
		expected    bool
	}{
		{
			name:        "zero targets",
			targetCount: 0,
			operation:   "CREATE",
			expected:    true,
		},
		{
			name:        "two targets",
			targetCount: 2,
			operation:   "UPDATE",
			expected:    true,
		},
		{
			name:        "three targets",
			targetCount: 3,
			operation:   "DELETE",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := make([]templates.Target, tt.targetCount)
			for i := 0; i < tt.targetCount; i++ {
				targets[i] = templates.Target{
					Target: "target" + string(rune('1'+i)),
				}
			}

			tc := &templateClient{
				template: &templates.ConstraintTemplate{
					Spec: templates.ConstraintTemplateSpec{
						Targets: targets,
					},
				},
			}

			result := tc.MatchesOperation(tt.operation)

			if result != tt.expected {
				t.Errorf("MatchesOperation with %d targets = %v, expected %v (backward compatibility)",
					tt.targetCount, result, tt.expected)
			}
		})
	}
}

// Benchmark test to ensure the function is performant.
func BenchmarkTemplateClient_MatchesOperation(b *testing.B) {
	tc := &templateClient{
		template: &templates.ConstraintTemplate{
			Spec: templates.ConstraintTemplateSpec{
				Targets: []templates.Target{
					{
						Target: "admission.k8s.gatekeeper.sh",
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
							admissionregistrationv1.Delete,
							admissionregistrationv1.Connect,
						},
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc.MatchesOperation("UPDATE")
	}
}
