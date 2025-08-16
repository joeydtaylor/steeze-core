package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Hermes semantics (no sinks)
func (c *Config) validateHermes() error {
	if len(c.Routes) == 0 {
		return errors.New("no routes defined")
	}
	if err := c.validateRoutes(); err != nil {
		return err
	}

	// Receivers (optional block, but if present must be valid)
	for i := range c.Receivers {
		rc := c.Receivers[i]
		if strings.TrimSpace(rc.Address) == "" {
			return fmt.Errorf("receiver %d: address required", i)
		}
		if rc.BufferSize == 0 {
			c.Receivers[i].BufferSize = 1024
		}
		if rc.BufferSize < 0 {
			return fmt.Errorf("receiver %d: buffer_size must be >= 0", i)
		}
		if k := strings.TrimSpace(rc.AES256Hex); k != "" {
			if _, err := hex.DecodeString(k); err != nil || len(k) != 64 {
				return fmt.Errorf("receiver %d: aes256_key_hex must be 32 bytes (64 hex)", i)
			}
		}
		if rc.TLS != nil && rc.TLS.Enable {
			if strings.TrimSpace(rc.TLS.ServerCert) == "" || strings.TrimSpace(rc.TLS.ServerKey) == "" || strings.TrimSpace(rc.TLS.CA) == "" {
				return fmt.Errorf("receiver %d tls: server_cert, server_key, and ca are required when enable=true", i)
			}
		}
		if rc.OAuth != nil {
			o := rc.OAuth
			switch o.Mode {
			case "", "off":
			case "jwt":
				if strings.TrimSpace(o.JWKSURL) == "" {
					return fmt.Errorf("receiver %d oauth: jwks_url required for mode=jwt", i)
				}
			case "introspect":
				if strings.TrimSpace(o.IntrospectURL) == "" {
					return fmt.Errorf("receiver %d oauth: introspect_url required for mode=introspect", i)
				}
				switch o.AuthType {
				case "basic":
					if o.ClientID == "" || o.ClientSecret == "" {
						return fmt.Errorf("receiver %d oauth: client_id/client_secret required for basic introspection", i)
					}
				case "bearer":
					if o.BearerToken == "" {
						return fmt.Errorf("receiver %d oauth: bearer_token required for bearer introspection", i)
					}
				default:
					return fmt.Errorf("receiver %d oauth: auth_type must be 'basic' or 'bearer' for mode=introspect", i)
				}
			case "merge":
				if strings.TrimSpace(o.JWKSURL) == "" || strings.TrimSpace(o.IntrospectURL) == "" {
					return fmt.Errorf("receiver %d oauth: merge requires jwks_url + introspect_url", i)
				}
			default:
				return fmt.Errorf("receiver %d oauth: unknown mode %q", i, o.Mode)
			}
			if o.JWKSCacheSecs == 0 {
				o.JWKSCacheSecs = 300
			}
			if o.CacheSecs == 0 {
				o.CacheSecs = 300
			}
		}
		if len(rc.Pipeline) == 0 {
			return fmt.Errorf("receiver %d: at least one pipeline required", i)
		}
		for j := range rc.Pipeline {
			p := rc.Pipeline[j]
			if strings.TrimSpace(p.DataType) == "" {
				return fmt.Errorf("receiver %d pipeline %d: datatype required", i, j)
			}
			if _, ok := TypeReg[p.DataType]; !ok {
				return fmt.Errorf("receiver %d pipeline %d: datatype %q not registered", i, j, p.DataType)
			}
			if len(p.Transformers) == 0 {
				return fmt.Errorf("receiver %d pipeline %d: transformers required", i, j)
			}
			// Output optional in Hermes semantics
		}
	}

	// Sinks must NOT be present in Hermes semantics
	if len(c.Sinks) > 0 {
		return errors.New("sinks are not supported under Hermes semantics")
	}
	return nil
}
