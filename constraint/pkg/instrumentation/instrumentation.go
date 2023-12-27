// package instrumentation defines primitives to
// support more observability throughout the constraint framework.
package instrumentation

import "github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego/schema"

const (
	// scope constants.

	// TemplateScope means the stat is associated with a template.
	TemplateScope = "template"
	// ConstraintScope means the stat is associated with a constraint.
	ConstraintScope = "constraint"

	// description constants.
	UnknownDescription = "unknown description"

	// source constants.
	EngineSourceType  = "engine"
	MatcherSourceType = "matcher"
)

var RegoSource = Source{
	Type:  EngineSourceType,
	Value: schema.Name,
}

// Label is a name/value tuple to add metadata
// about a StatsEntry.
type Label struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

// Source is a special Stat level label of the form type/value
// that is meant to be used to identify where a Stat is coming from.
type Source struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Stat is a Name, Value, Source tuple that may contain
// metrics or aggregations of metrics.
type Stat struct {
	Name   string      `json:"name"`
	Value  interface{} `json:"value"`
	Source Source      `json:"source"`
}

// StatsEntry comprises of a generalized Key for all associated Stats.
type StatsEntry struct {
	// Scope is the level of granularity that the Stats
	// were created at.
	Scope string `json:"scope"`
	// StatsFor is the name of the object that the stats are
	// gathered for.
	StatsFor string   `json:"statsFor"`
	Stats    []*Stat  `json:"stats"`
	Labels   []*Label `json:"labels,omitempty"`
}

// Adds labels to the StatsEntry s.
func (s *StatsEntry) AddLabels(labels ...*Label) {
	if s != nil {
		for _, l := range labels {
			if s.Labels == nil || len(s.Labels) == 0 {
				s.Labels = []*Label{}
			}

			s.Labels = append(s.Labels, l)
		}
	}
}
