package regolib

const (
	TargetLibSrcPath = "hooks.hooks_builtin"

	TargetLibSrc = `
package hooks

# Determine if the object under review violates constraint.
violation[response] {
  review := object.get(input, "review", {})

  key := object.get(input, "constraint", {})
  constraintKind := object.get(key, "kind", "")
  constraintName := object.get(key, "name", "")
  constraint := data.constraints[constraintKind][constraintName]

	inp := {
		"review": review,
		"parameters": object.get(object.get(constraint, "spec", {}), "parameters", {}),
	}
	inventory[inv]
	data.templates[constraint.kind].violation[r] with input as inp with data.inventory as inv

	spec := object.get(constraint, "spec", {})
	enforcementAction := object.get(spec, "enforcementAction", "deny")

  details := {"details": object.get(r, "details", {})}

	response = {
		"msg": r.msg,
		"metadata": details,
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
