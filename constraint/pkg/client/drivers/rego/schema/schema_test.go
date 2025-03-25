package schema

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
)

func TestGetSourceVersions(t *testing.T) {
	testCases := map[string]struct {
		Code            templates.Code
		ExpectedVersion string
	}{
		"v0": {
			ExpectedVersion: "v0",
			Code: templates.Code{
				Engine: Name,
				Source: &templates.Anything{
					Value: (&Source{
						Rego:    `pacakge foo`,
						Version: "v0",
						Libs:    nil,
					}).ToUnstructured(),
				},
			},
		},
		"v1": {
			ExpectedVersion: "v1",
			Code: templates.Code{
				Engine: Name,
				Source: &templates.Anything{
					Value: (&Source{
						Rego:    `pacakge foo`,
						Version: "v1",
						Libs:    nil,
					}).ToUnstructured(),
				},
			},
		},
		"v0 default, blank": {
			ExpectedVersion: "v0",
			Code: templates.Code{
				Engine: Name,
				Source: &templates.Anything{
					Value: (&Source{
						Rego:    `pacakge foo`,
						Version: "",
						Libs:    nil,
					}).ToUnstructured(),
				},
			},
		},
		"v0 default, missing": {
			ExpectedVersion: "v0",
			Code: templates.Code{
				Engine: Name,
				Source: &templates.Anything{
					Value: (&Source{
						Rego: `pacakge foo`,
						Libs: nil,
					}).ToUnstructured(),
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			source, err := GetSource(tc.Code)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if source.Version != tc.ExpectedVersion {
				t.Fatalf("expected version %s, got %s", tc.ExpectedVersion, source.Version)
			}
		})
	}
}
