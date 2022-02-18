package local

import (
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown/print"
	opatypes "github.com/open-policy-agent/opa/types"
)

type Arg func(*Driver) error

func Defaults() Arg {
	return func(d *Driver) error {
		if d.storage == nil {
			d.storage = inmem.New()
		}

		if d.capabilities == nil {
			d.capabilities = ast.CapabilitiesForThisVersion()
		}

		if d.externs == nil {
			for allowed := range validDataFields {
				d.externs = append(d.externs, fmt.Sprintf("data.%s", allowed))
			}
		}

		// adding external_data builtin otherwise capabilities get overridden
		// if a capability, like http.send, is disabled
		if d.providerCache != nil {
			d.capabilities.Builtins = append(d.capabilities.Builtins, &ast.Builtin{
				Name: "external_data",
				Decl: opatypes.NewFunction(opatypes.Args(opatypes.A), opatypes.A),
			})
		}

		return nil
	}
}

func Tracing(enabled bool) Arg {
	return func(d *Driver) error {
		d.traceEnabled = enabled

		return nil
	}
}

func PrintEnabled(enabled bool) Arg {
	return func(d *Driver) error {
		d.printEnabled = enabled

		return nil
	}
}

func PrintHook(hook print.Hook) Arg {
	return func(d *Driver) error {
		d.printHook = hook

		return nil
	}
}

func Storage(s storage.Store) Arg {
	return func(d *Driver) error {
		d.storage = s

		return nil
	}
}

func AddExternalDataProviderCache(providerCache *externaldata.ProviderCache) Arg {
	return func(d *Driver) error {
		d.providerCache = providerCache

		return nil
	}
}

func DisableBuiltins(builtins ...string) Arg {
	return func(d *Driver) error {
		if d.capabilities == nil {
			d.capabilities = ast.CapabilitiesForThisVersion()
		}

		disableBuiltins := make(map[string]bool)
		for _, b := range builtins {
			disableBuiltins[b] = true
		}

		var nb []*ast.Builtin
		builtins := d.capabilities.Builtins
		for i, b := range builtins {
			if !disableBuiltins[b.Name] {
				nb = append(nb, builtins[i])
			}
		}

		d.capabilities.Builtins = nb

		return nil
	}
}

// Externs sets the fields under `data` that Rego in ConstraintTemplates
// can access. If unset, all fields can be accessed. Only fields recognized by
// the system can be enabled.
func Externs(externs ...string) Arg {
	return func(driver *Driver) error {
		fields := make([]string, len(externs))

		for i, field := range externs {
			if !validDataFields[field] {
				return fmt.Errorf("%w: invalid data field %q; allowed fields are: %v",
					errors.ErrCreatingDriver, field, validDataFields)
			}

			fields[i] = fmt.Sprintf("data.%s", field)
		}

		driver.externs = fields

		return nil
	}
}

// Currently rules should only access data.inventory.
var validDataFields = map[string]bool{
	"inventory": true,
}
