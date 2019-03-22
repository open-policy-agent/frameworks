package regolib

const (
	targetLibSrc = `
package hooks["{{.Target}}"]

# Finds all violations for a given target
deny[response] {
	data.hooks["{{.Target}}"].library.matching_constraints[constraint]
	inp := {
		"review": get_default(input, "review", {}),
		"constraint": constraint
	}
	data.templates["{{.Target}}"][constraint.kind].deny[r] with input as inp
	response = {
		"msg": r.msg,
		"metadata": {"details": get_default(r, "details", {})},
		"constraint": constraint
	}
}


# Finds all violations in the cached state of a given target
audit[response] {
	data.hooks["{{.Target}}"].library.matching_reviews_and_constraints[[review, constraint]]
	inp := {
		"review": review,
		"constraint": constraint,
	}
	data.templates["{{.Target}}"][constraint.kind].deny[r] with input as inp
	response = {
		"msg": r.msg,
		"metadata": {"details": get_default(r, "details", {})},
		"constraint": constraint,
		"review": review,
	}
}


# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = object[field]

get_default(object, field, _default) = _default {
  not has_field(object, field)
}

has_field(object, field) {
  _ = object[field]
}
`
)
