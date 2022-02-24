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
	spec := object.get(constraint, "spec", {})

	inp := {
		"review": review,
		"parameters": object.get(spec, "parameters", {}),
	}
	inventory[inv]
	data.templates[constraint.kind].violation[r] with input as inp with data.inventory as inv

  details := {"details": object.get(r, "details", {})}

	response = {
		"msg": r.msg,
		"metadata": details,
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
