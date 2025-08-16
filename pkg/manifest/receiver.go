package manifest

// ReceiverTLS configures TLS termination for a receiver.
type ReceiverTLS struct {
	Enable     bool   `toml:"enable"`
	ServerCert string `toml:"server_cert"`
	ServerKey  string `toml:"server_key"`
	CA         string `toml:"ca"`
	ServerName string `toml:"server_name"`
}

// ReceiverOAuth config for the incoming hop.
type ReceiverOAuth struct {
	Mode           string   `toml:"mode"` // "off" | "jwt" | "introspect" | "merge"
	IssuerBase     string   `toml:"issuer_base"`
	JWKSURL        string   `toml:"jwks_url"`
	RequiredAud    []string `toml:"required_aud"`
	RequiredScopes []string `toml:"required_scopes"`
	JWKSCacheSecs  int      `toml:"jwks_cache_seconds"`
	IntrospectURL  string   `toml:"introspect_url"`
	AuthType       string   `toml:"auth_type"` // "basic" | "bearer"
	ClientID       string   `toml:"client_id"`
	ClientSecret   string   `toml:"client_secret"`
	BearerToken    string   `toml:"bearer_token"`
	CacheSecs      int      `toml:"cache_seconds"`
}

// ReceiverPipeline describes one pipeline branch for a receiver.
type ReceiverPipeline struct {
	DataType     string   `toml:"datatype"`     // must be registered in TypeReg
	Transformers []string `toml:"transformers"` // names registered in transform registry
	Output       string   `toml:"output"`       // named wire (required for Exodus semantics; optional for Hermes semantics)
}

// Receiver describes a receiving hop (HTTP server) and its pipeline branches.
type Receiver struct {
	Address    string             `toml:"address"`     // host:port
	BufferSize int                `toml:"buffer_size"` // default 1024 if 0
	AES256Hex  string             `toml:"aes256_key_hex"`
	TLS        *ReceiverTLS       `toml:"tls"`
	OAuth      *ReceiverOAuth     `toml:"oauth"`
	Pipeline   []ReceiverPipeline `toml:"pipeline"`
}
