package handlertest

import "text/template"

var libTempl = template.Must(template.New("library").Parse(`
package foo

matching_constraints[constraint] {
  constraint = {{.ConstraintsRoot}}[_][_]
  spec := object.get(constraint, "spec", {})
  matchNamespace := object.get(spec, "matchNamespace", "")
  review := object.get(input, "review", {})
  matches_namespace(review, matchNamespace)
}

matches_namespace(review, matchNamespace) = true {
  matchNamespace == ""
}

matches_namespace(review, matchNamespace) = true {
  matchNamespace != ""
  namespace := object.get(review.object, "namespace", "")
  namespace == matchNamespace
}

# Cluster scope
matching_reviews_and_constraints[[review, constraint]] {
  review := {"object": {{.DataRoot}}.cluster[_]}
  matching_constraints[constraint] with input as {"review": review}
}

matching_reviews_and_constraints2[review] {
  review := {"object": {{.DataRoot}}.cluster[_]}
  constraint := object.get(input, "constraint", {})
  spec := object.get(constraint, "spec", {})
  matchNamespace := object.get(spec, "matchNamespace", "")
  matches_namespace(review, matchNamespace)
}

# Namespace scope
matching_reviews_and_constraints[[review, constraint]] {
  review := {"object": {{.DataRoot}}.namespace[_][_]}
  matching_constraints[constraint] with input as {"review": review}
}

matching_reviews_and_constraints2[review] {
  review := {"object": {{.DataRoot}}.namespace[_][_]}
  constraint := object.get(input, "constraint", {})
  spec := object.get(constraint, "spec", {})
  matchNamespace := object.get(spec, "matchNamespace", "")
  matches_namespace(review, matchNamespace)
}

`))
