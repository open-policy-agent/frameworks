package client

import (
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ TargetHandler = &handler{}

type handler struct{}

func (h *handler) GetName() string {
	return "test.target"
}

var libTempl = template.Must(template.New("library").Parse(`
package foo

`))

func (h *handler) Library() *template.Template {
	return libTempl
}

func (h *handler) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	return true, "", map[string]interface{}{
		"object": obj,
	}, nil
}

func (h *handler) HandleReview(obj interface{}) (bool, interface{}, error) {
	handled, _, review, err := h.ProcessData(obj)
	return handled, review, err
}

func (h *handler) HandleViolation(result *types.Result) error {
	result.Resource = result.Review
	return nil
}

func (h *handler) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"label": {Type: "string"},
		},
	}
}

func (h *handler) ValidateConstraint(u *unstructured.Unstructured) error {
	return nil
}
