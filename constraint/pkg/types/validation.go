package types

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

type Result struct {
	Msg string `json:"msg,omitempty"`

	// Metadata includes the contents of `details` from the Rego rule signature
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// The constraint that was violated
	Constraint unstructured.Unstructured `json:"constraint,omitempty"`

	// The violating resource
	Resource interface{} `json:"resource,omitempty"`
}
