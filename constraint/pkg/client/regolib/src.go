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


# has_field returns whether an object has a field
has_field(object, field) = true {
  object[field]
}

# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
has_field(object, field) = true {
  object[field] == false
}

has_field(object, field) = false {
  not object[field]
  not object[field] == false
}



# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = output {
  has_field(object, field)
  output = object[field]
}

get_default(object, field, _default) = output {
  has_field(object, field) == false
  output = _default
}
`
)
