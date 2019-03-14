package regolib

const (
	// Finds all violations for a given target
	denySrc = `
package hooks.{{.Target}}

deny[response] {
	data.hooks.{{.Target}}.library.matching_constraints[constraint]
	data.templates.{{.Target}}[_].deny[response] with input.constraint as constraint
}
`

	// Runs audit on a given target
	auditSrc = `
package hooks.{{.Target}}

audit[response] {
	data.hooks.{{.Target}}.library.matching_reviews_and_constraints[[review, constraint]]
	cnst_key := ["constraint"]
	keys := [k | review[k]]
	all_keys := array.concat(cnst_key, keys)
	full_review := {k: v | v = audit_field_or_constraint(k, review, constraint); k = all_keys[_]}
	review.constraint = constraint
	data.templates.{{.Target}}[_].deny[response] with input as review
}

audit_field_or_constraint(key, review, constraint) = val {
	key == "constraint"
	val = constraint
}

audit_field_or_constraint(key, review, constraint) = val {
	key != "constraint"
	val = review[key]
}
`
)
