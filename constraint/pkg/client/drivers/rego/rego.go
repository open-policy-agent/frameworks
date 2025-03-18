package rego

import "github.com/open-policy-agent/opa/v1/ast"

const (
	// templatePath is the path the Template's Rego code is stored.
	// Must match the "data.xxx.violation[r]" path in hookModule.
	templatePath = "template"

	// templateLibPrefix is the path under which library Rego code is stored.
	// Must match "data.xxx.[library package]" path.
	templateLibPrefix = "libs"

	// hookModulePath.
	hookModulePath = "hooks.hooks_builtin"

	// hookModule specifies how Template violations are run in Rego.
	// This removes boilerplate that would otherwise need to be present in every
	// Template's Rego code. The violation's response is written to a standard
	// location we can read from to see if any violations occurred.
	hookModuleRego = `package hooks

# Determine if the object under review violates any passed Constraints.
violation contains response if {
	# Iterate over all keys to Constraints in storage.
	some key in input.constraints

	# Construct the input object from the Constraint and temporary object in storage.
	# Silently exits if the Constraint no longer exists.
	inp := {
		"review": input.review,
		"parameters": data.constraints[key.kind][key.name],
	}

	# Run the Template with Constraint.
	some r in data.template.violation with input as inp

	# Construct the response, defaulting "details" to empty object if it is not
	# specified.
	response := {
		"key": key,
		"details": object.get(r, "details", {}),
		"msg": r.msg,
	}
}
`
)

var hookModule *ast.Module

func init() {
	var err error
	hookModule, err = parseModule(hookModulePath, ast.RegoV1, hookModuleRego)
	if err != nil {
		panic(err)
	}
}
