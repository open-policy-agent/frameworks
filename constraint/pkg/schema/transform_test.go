/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package schema

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/utils/pointer"
)

func TestAddPreserveUnknownFields(t *testing.T) {
	testCases := []struct {
		name  string
		v     *apiextensionsv1.JSONSchemaProps
		exp   *apiextensionsv1.JSONSchemaProps
		error bool
	}{
		{
			name: "no information",
			v:    &apiextensionsv1.JSONSchemaProps{},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
			},
		},
		{
			name: "nil properties",
			v: &apiextensionsv1.JSONSchemaProps{
				Properties: nil,
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				Properties:             nil,
			},
		},
		{
			name: "x-kubernetes-preserve-unknown-fields is present already and true",
			v: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
			},
		},
		{
			name: "type object with no Properties",
			v: &apiextensionsv1.JSONSchemaProps{
				Type: "object",
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				Type:                   "object",
			},
		},
		{
			name: "type array with no Items",
			v: &apiextensionsv1.JSONSchemaProps{
				Type: "array",
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				Type: "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						XPreserveUnknownFields: pointer.Bool(true),
					},
				},
			},
		},
		{
			name: "type array with Items but no schemas",
			v: &apiextensionsv1.JSONSchemaProps{
				Type:  "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				Type: "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						XPreserveUnknownFields: pointer.Bool(true),
					},
				},
			},
		},
		{
			name: "map with empty JSONSchemaProps value",
			v: &apiextensionsv1.JSONSchemaProps{
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {
						XPreserveUnknownFields: pointer.Bool(true),
					},
				},
			},
		},
		{
			name: "Items with no type: array",
			v: &apiextensionsv1.JSONSchemaProps{
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
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Type:                   "object",
						XPreserveUnknownFields: pointer.Bool(true),
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"key":          {Type: "string"},
							"allowedRegex": {Type: "string"},
						},
					},
				},
			},
		},
		{
			name: "Recuse through doubly-nested properties",
			v: &apiextensionsv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"bar": {
								Type: "string",
							},
						},
					},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				Type:                   "object",
				XPreserveUnknownFields: pointer.Bool(true),
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {
						Type:                   "object",
						XPreserveUnknownFields: pointer.Bool(true),
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"bar": {
								Type: "string",
							},
						},
					},
				},
			},
		},
		{
			name: "Recurse through triply-nested properties",
			v: &apiextensionsv1.JSONSchemaProps{
				Type: "object",
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"bar": {
								Type: "object",
								Properties: map[string]apiextensionsv1.JSONSchemaProps{
									"burrito": {
										Type: "string",
									},
								},
							},
						},
					},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				Type:                   "object",
				XPreserveUnknownFields: pointer.Bool(true),
				Properties: map[string]apiextensionsv1.JSONSchemaProps{
					"foo": {
						Type:                   "object",
						XPreserveUnknownFields: pointer.Bool(true),
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"bar": {
								Type:                   "object",
								XPreserveUnknownFields: pointer.Bool(true),
								Properties: map[string]apiextensionsv1.JSONSchemaProps{
									"burrito": {
										Type: "string",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Recurse through doubly-nested Items with no type information",
			v: &apiextensionsv1.JSONSchemaProps{
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Items: &apiextensionsv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						XPreserveUnknownFields: pointer.Bool(true),
						Items: &apiextensionsv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
				},
			},
		},
		{
			name: "Recurse through doubly-nested Items with array type",
			v: &apiextensionsv1.JSONSchemaProps{
				Type: "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextensionsv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				Type: "array",
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "array",
						Items: &apiextensionsv1.JSONSchemaPropsOrArray{
							Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "string",
							},
						},
					},
				},
			},
		},
		{
			name: "Recurse through doubly-nested AdditionalProperties",
			v: &apiextensionsv1.JSONSchemaProps{
				AdditionalProperties: &apiextensionsv1.JSONSchemaPropsOrBool{
					Schema: &apiextensionsv1.JSONSchemaProps{
						AdditionalProperties: &apiextensionsv1.JSONSchemaPropsOrBool{
							Allows: false,
						},
					},
				},
			},
			exp: &apiextensionsv1.JSONSchemaProps{
				XPreserveUnknownFields: pointer.Bool(true),
				AdditionalProperties: &apiextensionsv1.JSONSchemaPropsOrBool{
					Schema: &apiextensionsv1.JSONSchemaProps{
						XPreserveUnknownFields: pointer.Bool(true),
						AdditionalProperties: &apiextensionsv1.JSONSchemaPropsOrBool{
							Allows: false,
						},
					},
				},
			},
		},
		{
			name: "JSONSchemas not supported",
			v: &apiextensionsv1.JSONSchemaProps{
				Items: &apiextensionsv1.JSONSchemaPropsOrArray{
					JSONSchemas: []apiextensionsv1.JSONSchemaProps{},
				},
			},
			error: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := AddPreserveUnknownFields(tc.v); err != nil {
				if tc.error {
					return
				}

				t.Errorf("Conversion error: %v", err)
			}

			if !reflect.DeepEqual(tc.v, tc.exp) {
				t.Errorf("Conversion does not match expected result: %v", cmp.Diff(tc.v, tc.exp))
			}
		})
	}
}
