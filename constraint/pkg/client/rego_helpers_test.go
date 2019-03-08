package client

import "testing"

type regoTestCase struct {
	Name          string
	Rego          string
	Path          string
	ErrorExpected bool
	ExpectedRego  string
}

func runRegoTests(tt []regoTestCase, t *testing.T) {
	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			path := tc.Path
			if path == "" {
				path = "default.test.path"
			}
			rego, err := ensureRegoConformance("test", path, tc.Rego)
			if (err == nil) && tc.ErrorExpected {
				t.Errorf("err = nil; want non-nil")
			}
			if (err != nil) && !tc.ErrorExpected {
				t.Errorf("err = \"%s\"; want nil", err)
			}
			if tc.ExpectedRego != "" && rego != tc.ExpectedRego {
				t.Errorf("ensureRegoConformance(%s) = %s; want %s", tc.Rego, rego, tc.ExpectedRego)
			}
		})
	}
}

func TestDataAccess(t *testing.T) {
	runRegoTests([]regoTestCase{
		{
			Name:          "Empty String Fails",
			Rego:          "",
			ErrorExpected: true,
		},
		{
			Name:          "No Data Access",
			Rego:          "package hello v{1 == 1}",
			ErrorExpected: false,
		},
		{
			Name:          "Valid Data Access: Inventory",
			Rego:          "package hello v{data.inventory == 1}",
			ErrorExpected: false,
		},
		{
			Name:          "Valid Data Access Field",
			Rego:          `package hello v{data["inventory"] == 1}`,
			ErrorExpected: false,
		},
		{
			Name:          "Valid Data Access Field Variable Assignment",
			Rego:          `package hello v{q := data["inventory"]; q.res == 7}`,
			ErrorExpected: false,
		},
		{
			Name:          "Invalid Data Access",
			Rego:          "package hello v{data.tribble == 1}",
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access Param",
			Rego:          `package hello v[{"here": data.onering}]{1 == 1}`,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access No Param",
			Rego:          `package hello v{data == 1}`,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access Variable",
			Rego:          `package hello v{q := "inventory"; data[q] == 1}`,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access Variable Assignment",
			Rego:          `package hello v{q := data; q.nonono == 1}`,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access Blank Iterator",
			Rego:          `package hello v{data[_] == 1}`,
			ErrorExpected: true,
		},
		{
			Name:          "Invalid Data Access Object",
			Rego:          `package hello v{data[{"my": _}] == 1}`,
			ErrorExpected: true,
		},
	}, t)
}

func TestNoImportsAllowed(t *testing.T) {
	runRegoTests([]regoTestCase{
		{
			Name:          "No Imports",
			Rego:          "package hello v{1 == 1}",
			ErrorExpected: false,
		},
		{
			Name:          "One Import",
			Rego:          "package hello import data.foo v{1 == 1}",
			ErrorExpected: true,
		},
		{
			Name:          "Three Imports",
			Rego:          "package hello import data.foo import data.test import data.things v{1 == 1}",
			ErrorExpected: true,
		},
	}, t)
}

func TestPackageChange(t *testing.T) {
	runRegoTests([]regoTestCase{
		{
			Name:          "Package Modified",
			Path:          "some.path",
			Rego:          "package hello v{1 == 1}",
			ErrorExpected: false,
			ExpectedRego: `package some.path

v = true { equal(1, 1) }`,
		},
		{
			Name:          "Package Modified Other Path",
			Path:          "different.path",
			Rego:          "package hello v{1 == 1}",
			ErrorExpected: false,
			ExpectedRego: `package different.path

v = true { equal(1, 1) }`,
		},
	}, t)
}
