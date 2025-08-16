package manifest

import (
	"fmt"
	"strings"
)

// validateRoutes runs shared route checks used by both Hermes and Exodus flows.
func (c *Config) validateRoutes() error {
	for i := range c.Routes {
		if err := c.Routes[i].normalize(); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		if err := c.Routes[i].validate(); err != nil {
			return fmt.Errorf("route %d (%s %s): %w", i, c.Routes[i].Method, c.Routes[i].Path, err)
		}
		if rs := c.Routes[i].Handler.Relay; rs != nil {
			if dt := strings.TrimSpace(rs.DataType); dt != "" {
				if _, ok := TypeReg[dt]; !ok {
					return fmt.Errorf("handler.relay.datatype %q not registered", dt)
				}
			}
			if len(rs.Transformers) > 0 {
				if strings.TrimSpace(rs.DataType) == "" {
					return fmt.Errorf("handler.relay.transformers specified but datatype is empty")
				}
				if _, ok := TypeReg[rs.DataType]; !ok {
					return fmt.Errorf("handler.relay.datatype %q not registered", rs.DataType)
				}
			}
		}
	}
	return nil
}
