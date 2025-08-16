// pkg/electrician/receiver_receive_env.go
package electrician

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

// receiverEnv is pure-data config for the Rx hop.
type receiverEnv struct {
	rxTLSEnable bool
	rxCrt       string
	rxKey       string
	rxCA        string
	rxName      string

	decKey []byte // optional

	issuer         string
	jwks           string
	introspectURL  string
	introspectAuth string
	clientID       string
	clientSecret   string
	bearer         string
	scopes         []string
	requiredAud    []string
	_              time.Duration // placeholder to match future extensions
}

func loadReceiverEnv() (receiverEnv, error) {
	var cfg receiverEnv

	cfg.rxTLSEnable = strings.EqualFold(os.Getenv("ELECTRICIAN_RX_TLS_ENABLE"), "true")
	cfg.rxCrt = envOr("ELECTRICIAN_RX_TLS_SERVER_CRT", "keys/tls/server.crt")
	cfg.rxKey = envOr("ELECTRICIAN_RX_TLS_SERVER_KEY", "keys/tls/server.key")
	cfg.rxCA = envOr("ELECTRICIAN_RX_TLS_CA", "keys/tls/ca.crt")
	cfg.rxName = os.Getenv("ELECTRICIAN_RX_TLS_SERVER_NAME")

	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return cfg, errors.New("receiver: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		cfg.decKey = raw
	}

	cfg.issuer = strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE"))
	cfg.jwks = strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
	cfg.introspectURL = strings.TrimSpace(os.Getenv("OAUTH_INTROSPECT_URL"))
	cfg.introspectAuth = envOr("OAUTH_INTROSPECT_AUTH", "basic")
	cfg.clientID = strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID"))
	cfg.clientSecret = strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET"))
	cfg.bearer = strings.TrimSpace(os.Getenv("OAUTH_INTROSPECT_BEARER"))
	cfg.scopes = splitCSV(os.Getenv("OAUTH_SCOPES"))
	cfg.requiredAud = splitCSV(os.Getenv("OAUTH_REQUIRED_AUD"))

	return cfg, nil
}
