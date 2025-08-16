package manifest

// Config is the top-level manifest (Hermes-only if Sinks is empty; Exodus when Sinks present).
type Config struct {
	Routes    []Route    `toml:"route"`
	Receivers []Receiver `toml:"receiver"`
	Sinks     []Sink     `toml:"sink"`
}

// Validate chooses semantics automatically:
// - If any sinks are present => Exodus semantics (wires required; sink cross-checks)
// - If no sinks             => Hermes semantics   (at least one route; no sink checks)
func (c *Config) Validate() error {
	if len(c.Sinks) > 0 {
		return c.validateExodus()
	}
	return c.validateHermes()
}
