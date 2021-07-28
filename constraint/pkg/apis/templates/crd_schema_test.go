package templates

import "testing"

func TestCRDSchema(t *testing.T) {
	// Confirm that the correct number of schemas are found
	const schemas = 3

	got := len(constraintTemplateCRD.Spec.Versions)
	if got != schemas {
		t.Fatalf("Got %v CRD versions, want %v", got, schemas)
	}
}
