package electrician

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"
)

// forwardEnv holds all inputs used to configure the forward hop.
type forwardEnv struct {
	targets       []string
	useTLS        bool
	tlsCrt        string
	tlsKey        string
	tlsCA         string
	tlsInsecure   bool
	useSnappy     bool
	useAESGCM     bool
	aesKey        string // string([]byte(32)) for builder API
	staticHeaders map[string]string

	// OAuth2 CC
	issuer       string
	jwks         string
	clientID     string
	clientSecret string
	scopes       []string
	leeway       time.Duration
	oauthEnabled bool
}

func loadForwardEnv() (forwardEnv, error) {
	f := forwardEnv{
		targets:       splitCSV(os.Getenv("ELECTRICIAN_TARGET")),
		useTLS:        strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_ENABLE"), "true"),
		tlsCrt:        envOr("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt"),
		tlsKey:        envOr("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key"),
		tlsCA:         envOr("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt"),
		tlsInsecure:   strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_INSECURE"), "true"),
		useSnappy:     strings.EqualFold(os.Getenv("ELECTRICIAN_COMPRESS"), "snappy"),
		useAESGCM:     strings.EqualFold(os.Getenv("ELECTRICIAN_ENCRYPT"), "aesgcm"),
		staticHeaders: parseKV(os.Getenv("ELECTRICIAN_STATIC_HEADERS")),

		issuer:       strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE")),
		jwks:         strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL")),
		clientID:     strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		clientSecret: strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET")),
		scopes:       splitCSV(os.Getenv("OAUTH_SCOPES")),
		leeway:       parseDur(envOr("OAUTH_REFRESH_LEEWAY", "20s")),
	}
	f.oauthEnabled = f.issuer != "" && f.clientID != "" && f.clientSecret != ""

	if f.useAESGCM {
		k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX"))
		raw, err := hex.DecodeString(k)
		if err != nil || len(raw) != 32 {
			return forwardEnv{}, errors.New("forward: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		f.aesKey = string(raw)
	}
	return f, nil
}

// receiverEnv holds inputs used to configure the receiver hop.
type receiverEnv struct {
	rxTLSEnable   bool
	rxCrt         string
	rxKey         string
	rxCA          string
	rxName        string
	decKey        string // string([]byte(32)) for builder API
	jwks          string
	introspectURL string
}

func loadReceiverEnv() (receiverEnv, error) {
	r := receiverEnv{
		rxTLSEnable:   strings.EqualFold(os.Getenv("ELECTRICIAN_RX_TLS_ENABLE"), "true"),
		rxCrt:         envOr("ELECTRICIAN_RX_TLS_SERVER_CRT", "keys/tls/server.crt"),
		rxKey:         envOr("ELECTRICIAN_RX_TLS_SERVER_KEY", "keys/tls/server.key"),
		rxCA:          envOr("ELECTRICIAN_RX_TLS_CA", "keys/tls/ca.crt"),
		rxName:        os.Getenv("ELECTRICIAN_RX_TLS_SERVER_NAME"),
		jwks:          strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL")),
		introspectURL: strings.TrimSpace(os.Getenv("OAUTH_INTROSPECT_URL")),
	}
	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return receiverEnv{}, errors.New("receiver: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		r.decKey = string(raw)
	}
	return r, nil
}
