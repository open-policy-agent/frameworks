package handlertest

// Review is the request to review Object.
type Review struct {
	Object Object `json:"object"`

	// Autoreject is whether this review should be autorejected if Autoreject is
	// enabled for the Constraint.
	Autoreject bool `json:"autoreject"`
}
