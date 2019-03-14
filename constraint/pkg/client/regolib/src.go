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
	inp := {
		"review": review,
		"constraint": constraint
	}
	data.templates.{{.Target}}[_].deny[response] with input as inp
}
`
)
