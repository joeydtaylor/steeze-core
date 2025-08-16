// pkg/electrician/env_helpers.go
package electrician

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// envOr returns the env var k or def if unset/empty.
func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseKV parses "k=v,k2=v2" into a map.
func parseKV(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		p := strings.SplitN(kv, "=", 2)
		if len(p) == 2 {
			out[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return out
}

// --- tiny env helpers (local to this file) ---

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurMs(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return def
}

// coalesce helpers for KAFKA_* that prefer specific vars over shared ones
func coalesceInt(v string, def int) int {
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func coalesceDurMs(v string, def time.Duration) time.Duration {
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return def
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if x := strings.TrimSpace(p); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func parseHeaders(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		p := strings.SplitN(kv, "=", 2)
		if len(p) == 2 {
			out[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	return out
}

func parseDur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	if d == 0 {
		d = 20 * time.Second
	}
	return d
}
