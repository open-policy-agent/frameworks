package regolib

const (
	// Finds all violations for a given target
	denySrc = `
package hooks.{{.Target}}

deny[response] {
	data.hooks.{{.Target}}.library.matching_constraints[constraint]
	data.templates.{{.Target}}[constraint.kind].deny[r] with input.constraint as constraint
	response = {
		"msg": r.msg,
		"metadata": {"details": r.details},
		"constraint": constraint
	}
}
`

	// Runs audit on a given target
	auditSrc = `
package hooks.{{.Target}}

audit[response] {
	data.hooks.{{.Target}}.library.matching_reviews_and_constraints[[review, constraint]]
	inp := {
		"review": review,
		"constraint": constraint,
	}
	data.templates.{{.Target}}[constraint.kind].deny[r] with input as inp
	response = {
		"msg": r.msg,
		"metadata": {"details": r.details},
		"constraint": constraint,
		"review": review,
	}
}
`
)
