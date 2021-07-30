package templates

import (
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

var (
	VersionedIncompleteSchema = &apiextensionsv1.JSONSchemaProps{
		Properties: map[string]apiextensionsv1.JSONSchemaProps{
			"message": {
				Type: "string",
			},
			"labels": {
				Type: "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"key":          {Type: "string"},
							"allowedRegex": {Type: "string"},
						},
					},
				},
			},
		},
	}

	trueBool                       = true
	VersionlessSchemaWithXPreserve = &apiextensions.JSONSchemaProps{
		XPreserveUnknownFields: &trueBool,
		Properties: map[string]apiextensions.JSONSchemaProps{
			"message": {
				Type: "string",
			},
			"labels": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type:                   "object",
						XPreserveUnknownFields: &trueBool,
						Properties: map[string]apiextensions.JSONSchemaProps{
							"key":          {Type: "string"},
							"allowedRegex": {Type: "string"},
						},
					},
				},
			},
		},
	}

	VersionlessSchema = &apiextensions.JSONSchemaProps{
		Properties: map[string]apiextensions.JSONSchemaProps{
			"message": {
				Type: "string",
			},
			"labels": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensions.JSONSchemaProps{
							"key":          {Type: "string"},
							"allowedRegex": {Type: "string"},
						},
					},
				},
			},
		},
	}
)
