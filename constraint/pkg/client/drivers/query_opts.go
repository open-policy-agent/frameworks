package drivers

type Options struct {
	DriverCfg *DriverCfg
	EngineCfg *EngineCfg
}

type EngineCfg struct {
	TracingEnabled bool
}

// Opt specifies optional arguments for constraint framework
// client APIs.
type Opt func(*Options)

// Tracing enables Rego tracing for a single query.
// If tracing is enabled for the Driver, Tracing(false) does not disable Tracing.
func Tracing(enabled bool) Opt {
	return func(cfg *Options) {
		if cfg.EngineCfg == nil {
			cfg.EngineCfg = &EngineCfg{}
		}
		cfg.EngineCfg.TracingEnabled = enabled
	}
}

type DriverCfg struct {
	StatsEnabled bool
}

// Stats(true) enables the driver to gather evaluation stats for a single
// query. If stats is enabled for the Driver at construction time, then
// Stats(false) does not disable Stats for this single query.
func Stats(enabled bool) Opt {
	return func(cfg *Options) {
		if cfg.DriverCfg == nil {
			cfg.DriverCfg = &DriverCfg{}
		}
		cfg.DriverCfg.StatsEnabled = enabled
	}
}
