package cts

import (
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/utils/pointer"
)

type PropMap map[string]apiextensions.JSONSchemaProps

func ExpectedSchema(pm PropMap) *apiextensions.JSONSchemaProps {
	pm["enforcementAction"] = apiextensions.JSONSchemaProps{Type: "string"}
	p := Prop(
		PropMap{
			"metadata": Prop(PropMap{
				"name": apiextensions.JSONSchemaProps{
					Type:      "string",
					MaxLength: pointer.Int64(63),
				},
			}),
			"spec":   Prop(pm),
			"status": {XPreserveUnknownFields: pointer.Bool(true)},
		},
	)
	return &p
}

// Prop constructs an Object schema node with the passed property map.
func Prop(pm map[string]apiextensions.JSONSchemaProps) apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{Type: "object", Properties: pm}
}

// PropUnstructured constructs a schema node with no specified underlying structure.
func PropUnstructured() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{XPreserveUnknownFields: pointer.Bool(true)}
}

// PropTyped creates a typed property with no subfields.
func PropTyped(t string) apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{Type: t}
}
