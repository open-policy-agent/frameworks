package client

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
)

// ensureRegoConformance rewrites the package path and ensures there is no access of `data`
// beyond the whitelisted bits. Note that this rewriting will currently modify the Rego to look
// potentially very different from the input, but it will still be functionally equivalent.
func ensureRegoConformance(kind, path, rego string) (string, error) {
	if rego == "" {
		return "", errors.New("Rego source code is empty")
	}
	module, err := ast.ParseModule(kind, rego)
	if err != nil {
		return "", err
	}
	if err := rewritePackage(path, module); err != nil {
		return "", err
	}
	if len(module.Imports) != 0 {
		return "", errors.New("Use of the `import` keyword is not allowed")
	}
	if err := checkDataAccess(module); err != nil {
		return "", err
	}
	return module.String(), nil
}

// rewritePackage rewrites the `package` statement in Rego with the provided package path
func rewritePackage(path string, module *ast.Module) error {
	if module.Package == nil {
		return errors.New("No `package` statement parsed")
	}
	pathParts := strings.Split(path, ".")
	packageRef := ast.EmptyRef()
	if pathParts[0] != "data" {
		packageRef = append(packageRef, ast.NewTerm(ast.String("data")))
	}
	for _, v := range pathParts {
		packageRef = append(packageRef, ast.NewTerm(ast.String(v)))
	}
	module.Package.Path = packageRef
	return nil
}

func makeInvalidRootFieldErr(val ast.Value, allowed map[string]bool) string {
	var validFields []string
	for field := range allowed {
		validFields = append(validFields, field)
	}
	return fmt.Sprintf("Invalid `data` field: %s. Valid fields are: %s", val.String(), strings.Join(validFields, ", "))
}

// checkDataAccess makes sure that data is only referenced in terms of valid subfields
func checkDataAccess(module *ast.Module) error {
	// Currently rules should only access data.inventory
	validDataFields := map[string]bool{
		"inventory": true,
	}

	var errs []string
	ast.WalkRefs(module, func(r ast.Ref) bool {
		if r.HasPrefix(ast.DefaultRootRef) {
			if len(r) < 2 {
				errs = append(errs, fmt.Sprintf("All references to `data` must access a field of `data`: %s", r))
				return false
			}
			if !r[1].IsGround() {
				errs = append(errs, fmt.Sprintf("Fields of `data` must be accessed with a literal value (e.g. `data.inventory`, not `data[var]`): %s", r))
				return false
			}
			v := r[1].Value
			if val, ok := v.(ast.String); !ok {
				errs = append(errs, makeInvalidRootFieldErr(v, validDataFields))
				return false
			} else {
				if !validDataFields[string(val)] {
					errs = append(errs, makeInvalidRootFieldErr(v, validDataFields))
					return false
				}
			}
		}
		return false
	})

	if len(errs) > 0 {
		return errors.New(strings.Join([]string(errs), "\n"))
	}
	return nil
}
