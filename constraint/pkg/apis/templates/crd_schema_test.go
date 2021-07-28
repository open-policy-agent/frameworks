package templates

import "testing"

func TestCRDIngestion(t *testing.T) {
	// Confirm that the correct number of schemas are found
	const schemas = 3

	got := len(constraintTemplateCRD.Spec.Versions)
	if got != schemas {
		t.Fatalf("Got %v CRD versions, want %v", got, schemas)
	}

	// Confirm that we can get a schema we expect
	_, err := getVersionSchema(constraintTemplateCRD.DeepCopy(), "v1")
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that an invalid version returns an error
	_, err = getVersionSchema(constraintTemplateCRD.DeepCopy(), "foobar")
	if err == nil {
		t.Fatal(err)
	}
}
