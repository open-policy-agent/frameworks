package regolib

const (
	TargetLibSrcPath = "hooks.hooks_builtin"

	TargetLibSrc = `
package hooks

# Determine if the object under review violates constraint.
violation[response] {
  key := input.constraints[_]

	inp := {
		"review": data.tmp[input.reviewKey],
		"parameters": data.constraints[key.kind][key.name].spec.parameters,
	}
	inventory[inv]
	data.templates[key.kind].violation[r] with input as inp with data.inventory as inv

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
