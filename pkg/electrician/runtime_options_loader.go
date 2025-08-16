package electrician

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

func LoadRuntimeOptionsFromEnv() (RuntimeOptions, error) {
	opt := RuntimeOptions{
		Targets:        splitCSV(os.Getenv("ELECTRICIAN_TARGET")),
		TLSEnable:      os.Getenv("ELECTRICIAN_TLS_ENABLE") == "true",
		TLSClientCrt:   getenv("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt"),
		TLSClientKey:   getenv("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key"),
		TLSCA:          getenv("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt"),
		TLSMin:         tls.VersionTLS13,
		TLSMax:         tls.VersionTLS13,
		InsecureTLS:    os.Getenv("ELECTRICIAN_TLS_INSECURE") == "true",
		CompressSnappy: os.Getenv("ELECTRICIAN_COMPRESS") == "snappy",
		EncryptAESGCM:  os.Getenv("ELECTRICIAN_ENCRYPT") == "aesgcm",

		OAuthIssuer:   os.Getenv("OAUTH_ISSUER_BASE"),
		OAuthJWKS:     os.Getenv("OAUTH_JWKS_URL"),
		OAuthClientID: os.Getenv("OAUTH_CLIENT_ID"),
		OAuthSecret:   os.Getenv("OAUTH_CLIENT_SECRET"),
		OAuthScopes:   splitCSV(os.Getenv("OAUTH_SCOPES")),
		OAuthLeeway:   parseDur(getenv("OAUTH_REFRESH_LEEWAY", "20s")),

		StaticHeaders: parseHeaders(os.Getenv("ELECTRICIAN_STATIC_HEADERS")), // "k=v,k2=v2"
	}

	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, err := hex.DecodeString(k)
		if err != nil {
			return RuntimeOptions{}, err
		}
		if len(raw) != 32 {
			return RuntimeOptions{}, errors.New("ELECTRICIAN_AES256_KEY_HEX must decode to 32 bytes")
		}
		opt.AESKey = raw
	}

	return opt, nil
}
