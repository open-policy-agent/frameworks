package regolib

const (
	TargetLibSrcPath = "hooks.hooks_builtin"

	TargetLibSrc = `
package hooks

# Determine if the object under review violates constraint.
violation[response] {
  constraint := data.constraints[input.constraint.kind][input.constraint.name]

	inp := {
		"review": data.tmp[input.reviewKey],
		"parameters": constraint.spec.parameters,
	}
	inventory[inv]
	data.templates[constraint.kind].violation[response] with input as inp with data.inventory as inv
}

inventory[inv] {
	inv = data.external
}

inventory[{}] {
	not data.external
}
`
)
