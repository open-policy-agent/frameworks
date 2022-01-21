package handlertest

// Object is a test object under review.
type Object struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// Data is checked by "CheckData" templates.
	Data string      `json:"data"`
	Root interface{} `json:"root"`
}
