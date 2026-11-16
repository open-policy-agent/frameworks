package rego

import (
	"errors"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	opatypes "github.com/open-policy-agent/opa/v1/types"
)

// ErrExternalDataRegisteredGlobally is returned by New when a Provider cache is
// configured and external_data is already a global OPA built-in, which would
// take precedence over the Driver's.
var ErrExternalDataRegisteredGlobally = errors.New("external_data is already registered as a global OPA built-in")

const externalDataName = "external_data"

var externalDataDecl = opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A)

// New constructs a new Driver. If a Provider cache is configured, external_data
// is bound to this Driver's queries rather than registered globally.
func New(args ...Arg) (*Driver, error) {
	d := &Driver{}
	for _, arg := range args {
		err := arg(d)
		if err != nil {
			return nil, err
		}
	}

	err := Defaults()(d)
	if err != nil {
		return nil, err
	}

	if d.providerCache != nil {
		if _, found := ast.BuiltinMap[externalDataName]; found {
			return nil, ErrExternalDataRegisteredGlobally
		}
		d.externalDataFunc = rego.Function1(
			&rego.Function{
				Name:    externalDataName,
				Decl:    externalDataDecl,
				Memoize: true,
			},
			externalDataBuiltin(d),
		)
	}

	return d, nil
}
