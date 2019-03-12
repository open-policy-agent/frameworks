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
	if len(module.Imports) != 0 {
		return "", errors.New("Use of the `import` keyword is not allowed")
	}
	// Temporarily unset Package.Path to avoid triggering a "prohibited data field" error
	module.Package.Path = nil
	if err := checkDataAccess(module); err != nil {
		return "", err
	}
	module.Package.Path = packageRef(path)
	return module.String(), nil
}

// packageRef constructs a Ref to the provided package path string
func packageRef(path string) ast.Ref {
	pathParts := strings.Split(path, ".")
	packageRef := ast.Ref([]*ast.Term{ast.VarTerm("data")})
	for _, v := range pathParts {
		packageRef = append(packageRef, ast.StringTerm(v))
	}
	return packageRef
}

func makeInvalidRootFieldErr(val ast.Value, allowed map[string]bool) error {
	var validFields []string
	for field := range allowed {
		validFields = append(validFields, field)
	}
	return fmt.Errorf("Invalid `data` field: %s. Valid fields are: %s", val.String(), strings.Join(validFields, ", "))
}

var _ error = Errors{}

type Errors []error

func (errs Errors) Error() string {
	s := make([]string, len(errs))
	for _, e := range errs {
		s = append(s, e.Error())
	}
	return strings.Join(s, "\n")
}

// checkDataAccess makes sure that data is only referenced in terms of valid subfields
func checkDataAccess(module *ast.Module) Errors {
	// Currently rules should only access data.inventory
	validDataFields := map[string]bool{
		"inventory": true,
	}

	var errs Errors
	ast.WalkRefs(module, func(r ast.Ref) bool {
		if r.HasPrefix(ast.DefaultRootRef) {
			if len(r) < 2 {
				errs = append(errs, fmt.Errorf("All references to `data` must access a field of `data`: %s", r))
				return false
			}
			if !r[1].IsGround() {
				errs = append(errs, fmt.Errorf("Fields of `data` must be accessed with a literal value (e.g. `data.inventory`, not `data[var]`): %s", r))
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
		return errs
	}
	return nil
}
