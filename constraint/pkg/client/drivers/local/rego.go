package local

const (
	// hookModulePath
	hookModulePath = "hooks.hooks_builtin"

	// hookModule specifies how Template violations are run in Rego.
	// This removes boilerplate that would otherwise need to be present in every
	// Template's Rego code. The violation's response is written to a standard
	// location we can read from to see if any violations occurred.
	hookModule = `
package hooks

# Determine if the object under review violates any passed Constraints.
violation[response] {
  # Iterate over all keys to Constraints in storage.
  key := input.constraints[_]

  # Construct the input object from the Constraint and temporary object in storage.
  # Silently exits if the Constraint no longer exists.
	inp := {
		"review": data.tmp[input.reviewKey],
		"parameters": data.constraints[key.kind][key.name],
	}
	inventory[inv]

  # Run the Template with Constraint.
	data.templates[key.kind].violation[r] with input as inp with data.inventory as inv

  # Construct the response, defaulting "details" to empty object if it is not
  # specified.
  response := {
    "key": key,
    "details": object.get(r, "details", {}),
    "msg": r.msg,
  }
}

# Default data.external to empty object. We can't directly reference "data" in
# object.get() without causing a circular dependency error in compilation.
inventory[inv] {
	inv = data.external
}

inventory[{}] {
	not data.external
}
`
)
