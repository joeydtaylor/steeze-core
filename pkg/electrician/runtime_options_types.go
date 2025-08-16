package electrician

import "time"

type RuntimeOptions struct {
	Targets []string

	// TLS
	TLSEnable    bool
	TLSClientCrt string
	TLSClientKey string
	TLSCA        string
	TLSMin       uint16
	TLSMax       uint16
	InsecureTLS  bool // dev only

	// Perf/Security
	CompressSnappy bool
	EncryptAESGCM  bool
	AESKey         []byte // 32 bytes

	// OAuth2 CC
	OAuthIssuer   string
	OAuthJWKS     string
	OAuthClientID string
	OAuthSecret   string
	OAuthScopes   []string
	OAuthLeeway   time.Duration

	// Static headers
	StaticHeaders map[string]string
}
