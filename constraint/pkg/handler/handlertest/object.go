package handlertest

import "github.com/open-policy-agent/frameworks/constraint/pkg/handler"

// Object is a test object under review. The idea is to represent objects just
// complex enough to showcase (and test) the features of frameworks's Client,
// Drivers, and Handlers.
type Object struct {
	// Name is the identifier of an Object within the scope of its Namespace
	// (if present). If unset, the Object is a special "Namespace" object.
	Name string `json:"name"`

	// Namespace is used for Constraints which apply to a subset of Objects.
	// If unset, the Object is not scoped to a Namespace.
	Namespace string `json:"namespace"`

	// Data is checked by "CheckData" templates.
	Data string `json:"data"`
}

func (o Object) Key() handler.Key {
	if o.Namespace == "" {
		return []string{"cluster", o.Name}
	}
	return []string{"namespace", o.Namespace, o.Name}
}
