package clienttest

import (
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ client.TargetHandler = &Handler{}

const HandlerName = "test.target"

type Handler struct{}

func (h *Handler) GetName() string {
	return HandlerName
}

var libTempl = template.Must(template.New("library").Parse(`
package foo

autoreject_review[rejection] {
	constraint := {{.ConstraintsRoot}}[_][_]
  constraint.spec.autoreject
  input.review.autoreject

	rejection := {
		"msg": "autoreject",
		"details": {},
		"constraint": constraint,
	}
}

matching_constraints[constraint] {
  constraint = {{.ConstraintsRoot}}[_][_]
  spec := object.get(constraint, "spec", {})
  matchNamespace := object.get(spec, "matchNamespace", "")
  matches_namespace(matchNamespace)
}

matches_namespace(matchNamespace) = true {
  matchNamespace == ""
}

matches_namespace(matchNamespace) = true {
  matchNamespace != ""
  namespace := object.get(input.review.object, "namespace", "")
  namespace == matchNamespace
}

# Cluster scope
matching_reviews_and_constraints[[review, constraint]] {
   review := {"object": {{.DataRoot}}.cluster[_]}
 	matching_constraints[constraint] with input as {"review": review}
}

# Namespace scope
matching_reviews_and_constraints[[review, constraint]] {
   review := {"object": {{.DataRoot}}.namespace[_][_]}
 	matching_constraints[constraint] with input as {"review": review}
}

has_field(object, field) = true {
	object[field]
}

has_field(object, field) = true {
  object[field] == false
}

has_field(object, field) = false {
  not object[field]
  not object[field] == false
}

`))

func (h *Handler) Library() *template.Template {
	return libTempl
}

func (h *Handler) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	switch o := obj.(type) {
	case *Object:
		if o.Namespace == "" {
			return true, fmt.Sprintf("cluster/%s", o.Name), obj, nil
		}
		return true, fmt.Sprintf("namespace/%s/%s", o.Namespace, o.Name), obj, nil
	default:
		return false, "", nil, fmt.Errorf("unrecognized type %T", obj)
	}
}

func (h *Handler) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch data := obj.(type) {
	case Review:
		return true, &data, nil
	case *Review:
		return true, data, nil
	default:
		return false, nil, fmt.Errorf("unrecognized type %T", obj)
	}
}

func (h *Handler) HandleViolation(result *types.Result) error {
	res, err := json.Marshal(result.Review)
	if err != nil {
		return err
	}

	d := &Review{}
	if err = json.Unmarshal(res, d); err != nil {
		return err
	}

	result.Resource = d
	return nil
}

func (h *Handler) MatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"label": {Type: "string"},
		},
	}
}

func (h *Handler) ValidateConstraint(_ *unstructured.Unstructured) error {
	return nil
}
