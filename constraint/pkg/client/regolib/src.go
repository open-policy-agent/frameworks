package regolib

const (
	TargetLibSrcPath = "hooks.hooks_builtin"

	TargetLibSrc = `
package hooks

# Determine if the object under review violates constraint.
violation[response] {
  key := input.constraints[_]
  constraint := data.constraints[key.kind][key.name]

	inp := {
		"review": data.tmp[input.reviewKey],
		"parameters": constraint.spec.parameters,
	}
	inventory[inv]
	data.templates[constraint.kind].violation[r] with input as inp with data.inventory as inv

  response := {
    "key": key,
    "details": object.get(r, "details", {}),
    "msg": r.msg,
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
