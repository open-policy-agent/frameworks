package clienttest

// Review is the request to review Object.
type Review struct {
	Object Object `json:"object"`

	// Autoreject is whether this review should be autorejected if Autoreject is
	// enabled for the Constraint.
	Autoreject bool `json:"autoreject"`
}

// Object is a test object under review.
type Object struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// Data is checked by "CheckData" templates.
	Data string `json:"data"`
	Root interface{} `json:"root"`
}
