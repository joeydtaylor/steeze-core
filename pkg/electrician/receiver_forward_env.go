// pkg/electrician/receiver_forward_env.go
package electrician

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

// forwardEnv is a pure-data config (no builder types).
type forwardEnv struct {
	targets          []string
	useTLS           bool
	tlsCrt           string
	tlsKey           string
	tlsCA            string
	tlsInsecure      bool
	useSnappy        bool
	useAESGCM        bool
	aesKey           []byte
	staticHeaders    map[string]string
	oauthEnabled     bool
	issuer           string
	jwksURL          string
	clientID         string
	clientSecret     string
	scopes           []string
	requiredAud      []string
	leeway           time.Duration
	preflightTimeout time.Duration
}

func loadForwardEnv() (forwardEnv, error) {
	var cfg forwardEnv

	cfg.targets = splitCSV(os.Getenv("ELECTRICIAN_TARGET"))
	cfg.useTLS = strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_ENABLE"), "true")
	cfg.tlsCrt = envOr("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt")
	cfg.tlsKey = envOr("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key")
	cfg.tlsCA = envOr("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt")
	cfg.tlsInsecure = strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_INSECURE"), "true")

	cfg.useSnappy = strings.EqualFold(os.Getenv("ELECTRICIAN_COMPRESS"), "snappy")
	cfg.useAESGCM = strings.EqualFold(os.Getenv("ELECTRICIAN_ENCRYPT"), "aesgcm")
	if cfg.useAESGCM {
		k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX"))
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return cfg, errors.New("forward: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		cfg.aesKey = raw
	}

	cfg.staticHeaders = parseKV(os.Getenv("ELECTRICIAN_STATIC_HEADERS"))

	cfg.issuer = strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE"))
	cfg.jwksURL = strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
	cfg.clientID = strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID"))
	cfg.clientSecret = strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET"))
	cfg.scopes = splitCSV(os.Getenv("OAUTH_SCOPES"))
	cfg.requiredAud = splitCSV(os.Getenv("OAUTH_REQUIRED_AUD"))
	cfg.leeway = parseDur(envOr("OAUTH_REFRESH_LEEWAY", "20s"))
	cfg.preflightTimeout = parseDur(envOr("OAUTH_PREFLIGHT_TIMEOUT", "8s"))
	cfg.oauthEnabled = cfg.issuer != "" && cfg.clientID != "" && cfg.clientSecret != ""

	return cfg, nil
}
