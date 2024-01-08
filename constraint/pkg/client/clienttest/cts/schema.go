package cts

import (
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/utils/ptr"
)

type PropMap map[string]apiextensions.JSONSchemaProps

func ExpectedSchema(pm PropMap) *apiextensions.JSONSchemaProps {
	pm["enforcementAction"] = apiextensions.JSONSchemaProps{Type: "string"}
	p := Prop(
		PropMap{
			"metadata": Prop(PropMap{
				"name": apiextensions.JSONSchemaProps{
					Type:      "string",
					MaxLength: ptr.To[int64](63),
				},
			}),
			"spec":   Prop(pm),
			"status": {XPreserveUnknownFields: ptr.To[bool](true)},
		},
	)
	return &p
}

// Prop constructs an Object schema node with the passed property map.
func Prop(properties map[string]apiextensions.JSONSchemaProps) apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{Type: "object", Properties: properties}
}

// PropUnstructured constructs a schema node with no specified underlying structure.
func PropUnstructured() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{XPreserveUnknownFields: ptr.To[bool](true)}
}

// PropTyped creates a typed property with no subfields.
func PropTyped(propType string) apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{Type: propType}
}
