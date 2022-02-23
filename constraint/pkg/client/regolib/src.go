package regolib

const (
	TargetLibSrcPath = "hooks.hooks_builtin"

	TargetLibSrc = `
package hooks

# Determine if the object under review violates constraint.
violation[response] {
  review := object.get(input, "review", {})
  constraint := object.get(input, "constraint", {})

	inp := {
		"review": review,
		"parameters": object.get(object.get(constraint, "spec", {}), "parameters", {}),
	}
	inventory[inv]
	data.templates[constraint.kind].violation[r] with input as inp with data.inventory as inv

	spec := object.get(constraint, "spec", {})
	enforcementAction := object.get(spec, "enforcementAction", "deny")

	response = {
		"msg": r.msg,
		"metadata": {"details": object.get(r, "details", {})},
		"constraint": constraint,
		"review": review,
		"enforcementAction": enforcementAction,
	}
}

inventory[inv] {
	inv = data.external
}

inventory[{}] {
	not data.external
}
`
)
