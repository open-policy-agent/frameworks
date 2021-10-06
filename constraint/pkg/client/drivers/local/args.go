package local

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

type Arg func(*driver)

func ArgDefaults() Arg {
	return func(d *driver) {
		if d.compiler == nil {
			d.compiler = ast.NewCompiler()
		}

		if d.modules == nil {
			d.modules = make(map[string]*ast.Module)
		}

		if d.storage == nil {
			d.storage = inmem.New()
		}

		if d.capabilities == nil {
			d.capabilities = ast.CapabilitiesForThisVersion()
		}
	}
}

func ArgCompiler(compiler *ast.Compiler) Arg {
	return func(d *driver) {
		d.compiler = compiler
	}
}

func ArgModules(modules map[string]*ast.Module) Arg {
	return func(d *driver) {
		d.modules = modules
	}
}

func ArgStorage(s storage.Store) Arg {
	return func(d *driver) {
		d.storage = s
	}
}

func ArgCapabilities(c *ast.Capabilities) Arg {
	return func(d *driver) {
		d.capabilities = c
	}
}

func Tracing(enabled bool) Arg {
	return func(d *driver) {
		d.traceEnabled = enabled
	}
}

func DisableBuiltins(builtins ...string) Arg {
	return func(d *driver) {
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
	}
}
