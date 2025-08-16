// manifest/manifest.go
package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/joeydtaylor/steeze-core/pkg/codec"
)

/* ===========================
   Types / registry
   =========================== */

type HandlerType string

type TypeBinding struct {
	Name  string
	Codec codec.Codec
	Zero  func() any
}

// TypeReg: register datatypes by name (used to validate RelaySpec.DataType and pipelines)
var TypeReg = make(map[string]TypeBinding)

const (
	HandlerInproc       HandlerType = "inproc"
	HandlerRelayReq     HandlerType = "relay.request"
	HandlerRelayPublish HandlerType = "relay.publish"
	HandlerProxy        HandlerType = "proxy"
)

/* ===========================
   Top-level config (superset)
   =========================== */

type Config struct {
	Routes    []Route    `toml:"route"`
	Receivers []Receiver `toml:"receiver"`
	Sinks     []Sink     `toml:"sink"`
}

/* ===========================
   HTTP routing
   =========================== */

type Route struct {
	Path    string   `toml:"path"`
	Method  string   `toml:"method"`
	Guard   Guard    `toml:"guard"`
	Policy  Policy   `toml:"policy"`
	Handler HSpec    `toml:"handler"`
	Codec   string   `toml:"codec"`
	Tags    []string `toml:"tags"`
}

type Guard struct {
	Roles       []string `toml:"roles"`
	Users       []string `toml:"users"`
	RequireAuth bool     `toml:"require_auth"`
}

type DownstreamAuth struct {
	Type     string   `toml:"type"`     // "none" | "passthrough-cookie" | "static-bearer" | "token-exchange"
	Scopes   []string `toml:"scopes"`   // for token-exchange
	Audience string   `toml:"audience"` // for token-exchange
	Header   string   `toml:"header"`   // for static-bearer custom header (default: Authorization)
}

type Policy struct {
	TimeoutMS   int             `toml:"timeout_ms"`
	Retry       *RetryPolicy    `toml:"retry"`
	RateLimit   *RateLimit      `toml:"rate_limit"`
	Breaker     *Breaker        `toml:"breaker"`
	ForwardHdrs []string        `toml:"forward_headers"`
	DownAuth    *DownstreamAuth `toml:"downstream_auth"`
}

type RetryPolicy struct {
	Attempts  int `toml:"attempts"`
	BackoffMS int `toml:"backoff_ms"`
}

type RateLimit struct {
	RPS   int `toml:"rps"`
	Burst int `toml:"burst"`
}

type Breaker struct {
	FailureRateThreshold float64 `toml:"failure_rate_threshold"`
	OpenForMS            int     `toml:"open_for_ms"`
}

type HSpec struct {
	Type  HandlerType `toml:"type"`
	Name  string      `toml:"name"`
	Proxy *ProxySpec  `toml:"proxy"`
	Relay *RelaySpec  `toml:"relay"`
}

type ProxySpec struct {
	URL         string   `toml:"url"`
	PassHeaders []string `toml:"pass_headers"`
}

type RelaySpec struct {
	Topic        string   `toml:"topic"`
	ExpectReply  bool     `toml:"expect_reply"`
	DeadlineMS   int      `toml:"deadline_ms"`
	DataType     string   `toml:"datatype,omitempty"`
	Transformers []string `toml:"transformers"` // optional publish-side transforms
}

/* ===========================
   Receiver / transformer
   =========================== */

type ReceiverTLS struct {
	Enable     bool   `toml:"enable"`
	ServerCert string `toml:"server_cert"`
	ServerKey  string `toml:"server_key"`
	CA         string `toml:"ca"`
	ServerName string `toml:"server_name"`
}

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

type ReceiverPipeline struct {
	DataType     string   `toml:"datatype"`     // must be registered in TypeReg
	Transformers []string `toml:"transformers"` // names registered in transform registry
	Output       string   `toml:"output"`       // named wire (required for Exodus semantics; optional for Hermes semantics)
}

type Receiver struct {
	Address    string             `toml:"address"`     // host:port
	BufferSize int                `toml:"buffer_size"` // default 1024 if 0
	AES256Hex  string             `toml:"aes256_key_hex"`
	TLS        *ReceiverTLS       `toml:"tls"`
	OAuth      *ReceiverOAuth     `toml:"oauth"`
	Pipeline   []ReceiverPipeline `toml:"pipeline"`
}

/* ===========================
   Sinks (fan-in consumers)
   =========================== */

type SinkType string

const (
	SinkTypeS3    SinkType = "s3"
	SinkTypeKafka SinkType = "kafka"
)

type Sink struct {
	Type   SinkType   `toml:"type"`            // "s3" | "kafka"
	Name   string     `toml:"name"`            // optional, for logging/metrics
	Inputs []string   `toml:"inputs"`          // wires to fan-in (must match ReceiverPipeline.output)
	S3     *S3Sink    `toml:"s3,omitempty"`    // for type == "s3"
	Kafka  *KafkaSink `toml:"kafka,omitempty"` // for type == "kafka"
}

/* ===== S3 sink ===== */

type S3Sink struct {
	Bucket           string `toml:"bucket"`
	PrefixTemplate   string `toml:"prefix_template"`
	Format           string `toml:"format"` // "parquet" (for now)
	MinutePartitions bool   `toml:"minute_partitions"`

	Batch   *S3Batch   `toml:"batch"`
	Parquet *Parquet   `toml:"parquet"`
	SSE     *SSE       `toml:"sse"`
	AWS     *AWSClient `toml:"aws"`

	// Dev/test toggles
	SimulatePutError bool `toml:"simulate_put_error"`
	SimulateBadKMS   bool `toml:"simulate_bad_kms"`
}

type S3Batch struct {
	MaxRecords int `toml:"max_records"`
	MaxBytes   int `toml:"max_bytes"`
	MaxAgeMS   int `toml:"max_age_ms"`
}

type Parquet struct {
	Compression    string `toml:"compression"`      // zstd|snappy|gzip
	RollWindowMS   int    `toml:"roll_window_ms"`   // time-based roll
	RollMaxRecords int    `toml:"roll_max_records"` // size-based roll
}

type SSE struct {
	Type        string `toml:"type"` // "aws:kms" | "s3" | "aes256"
	KMSAliasARN string `toml:"kms_alias_arn"`
}

type AWSClient struct {
	Region                string `toml:"region"`
	RoleARN               string `toml:"role_arn"`
	SessionName           string `toml:"session_name"`
	DurationMinutes       int    `toml:"duration_minutes"`
	EndpointURL           string `toml:"endpoint_url"`
	UsePathStyle          bool   `toml:"use_path_style"`
	StaticAccessKeyID     string `toml:"static_access_key_id"`
	StaticSecretAccessKey string `toml:"static_secret_access_key"`
	InsecureSkipTLSVerify bool   `toml:"insecure_skip_tls_verify"`
}

/* ===== Kafka sink ===== */

type KafkaSink struct {
	Brokers []string `toml:"brokers"` // e.g., ["127.0.0.1:19092"]
	Topic   string   `toml:"topic"`

	// Payload encoding
	Format string `toml:"format"` // "ndjson" (default) | "json"

	// Message key & headers
	KeyTemplate     string            `toml:"key_template"`
	HeaderTemplates map[string]string `toml:"headers"`

	// Batching
	Batch *KafkaBatch `toml:"batch"`

	// kafka-go writer tuning
	Writer *KafkaWriter `toml:"writer"`

	// Security
	Security *KafkaSecurity `toml:"security"`

	// Client identity
	ClientID string `toml:"client_id"` // default: "core-kafka-writer"
}

type KafkaBatch struct {
	MaxRecords int `toml:"max_records"`  // default: 10000
	MaxBytesMB int `toml:"max_bytes_mb"` // default: 16
	MaxAgeMS   int `toml:"max_age_ms"`   // default: 800
}

type KafkaWriter struct {
	BatchTimeoutMS int    `toml:"batch_timeout_ms"` // default: 400
	Balancer       string `toml:"balancer"`         // "least_bytes"(def) | "round_robin" | "hash"
}

type KafkaSecurity struct {
	TLS  *KafkaTLS  `toml:"tls"`
	SASL *KafkaSASL `toml:"sasl"`
}

type KafkaTLS struct {
	Enable             bool     `toml:"enable"`
	CAFiles            []string `toml:"ca_files"`
	ServerName         string   `toml:"server_name"`
	InsecureSkipVerify bool     `toml:"insecure_skip_tls_verify"`
	ClientCert         string   `toml:"client_cert"`
	ClientKey          string   `toml:"client_key"`
}

type KafkaSASL struct {
	Mechanism string `toml:"mechanism"` // "SCRAM-SHA-256" | "SCRAM-SHA-512" | "PLAIN"
	Username  string `toml:"username"`
	Password  string `toml:"password"`
}

/* ===========================
   Validation / Normalization
   =========================== */

// Validate chooses semantics automatically:
// - If any sinks are present => Exodus semantics (wires required; sink cross-checks)
// - If no sinks             => Hermes semantics   (at least one route; no sink checks)
func (c *Config) Validate() error {
	if len(c.Sinks) > 0 {
		return c.validateExodus()
	}
	return c.validateHermes()
}

/* ---------- Shared route checks ---------- */

func (r *Route) normalize() error {
	if r.Path == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(r.Path, "/") {
		r.Path = "/" + r.Path
	}
	if r.Path != "/" {
		r.Path = path.Clean(r.Path)
	}
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	if r.Method == "" {
		r.Method = "GET"
	}
	r.Codec = strings.ToLower(strings.TrimSpace(r.Codec))
	return nil
}

func (r *Route) validate() error {
	switch r.Handler.Type {
	case HandlerInproc:
		if strings.TrimSpace(r.Handler.Name) == "" {
			return errors.New("handler.name required for inproc")
		}
	case HandlerRelayReq, HandlerRelayPublish:
		if r.Handler.Relay == nil || strings.TrimSpace(r.Handler.Relay.Topic) == "" {
			return errors.New("handler.relay.topic required for relay")
		}
	case HandlerProxy:
		if r.Handler.Proxy == nil || strings.TrimSpace(r.Handler.Proxy.URL) == "" {
			return errors.New("handler.proxy.url required for proxy")
		}
	default:
		return fmt.Errorf("unknown handler type %q", r.Handler.Type)
	}

	if da := r.Policy.DownAuth; da != nil {
		switch da.Type {
		case "none", "passthrough-cookie", "static-bearer", "token-exchange":
		default:
			return fmt.Errorf("policy.downstream_auth.type %q invalid", da.Type)
		}
	}

	if r.Policy.TimeoutMS < 0 {
		return errors.New("policy.timeout_ms must be >= 0")
	}
	if rp := r.Policy.Retry; rp != nil {
		if rp.Attempts < 0 {
			return errors.New("policy.retry.attempts must be >= 0")
		}
		if rp.BackoffMS < 0 {
			return errors.New("policy.retry.backoff_ms must be >= 0")
		}
	}
	if rl := r.Policy.RateLimit; rl != nil {
		if rl.RPS < 0 || rl.Burst < 0 {
			return errors.New("policy.rate_limit values must be >= 0")
		}
	}
	if br := r.Policy.Breaker; br != nil {
		if br.FailureRateThreshold < 0 || br.FailureRateThreshold > 1 {
			return errors.New("policy.breaker.failure_rate_threshold must be in [0,1]")
		}
		if br.OpenForMS < 0 {
			return errors.New("policy.breaker.open_for_ms must be >= 0")
		}
	}
	return nil
}

/* ---------- Hermes semantics (no sinks) ---------- */

func (c *Config) validateHermes() error {
	if len(c.Routes) == 0 {
		return errors.New("no routes defined")
	}

	// Routes
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

/* ---------- Exodus semantics (sinks + wires) ---------- */

func (c *Config) validateExodus() error {
	// Routes optional; if present, validate
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

	// Receivers + collect wires
	wireSet := map[string]struct{}{}
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
			out := strings.TrimSpace(p.Output)
			if out == "" {
				return fmt.Errorf("receiver %d pipeline %d: output wire name required under Exodus semantics", i, j)
			}
			if _, exists := wireSet[out]; exists {
				return fmt.Errorf("receiver %d pipeline %d: duplicate output wire %q", i, j, out)
			}
			wireSet[out] = struct{}{}
		}
	}

	// Sinks: inputs must map to produced wires
	for i := range c.Sinks {
		s := c.Sinks[i]
		if len(s.Inputs) == 0 {
			return fmt.Errorf("sink %d: at least one input wire required", i)
		}
		for _, in := range s.Inputs {
			if _, ok := wireSet[strings.TrimSpace(in)]; !ok {
				return fmt.Errorf("sink %d: input wire %q not produced by any receiver.pipeline.output", i, in)
			}
		}
		switch s.Type {
		case SinkTypeS3:
			if s.S3 == nil {
				return fmt.Errorf("sink %d: s3 block required for type 's3'", i)
			}
			if strings.TrimSpace(s.S3.Bucket) == "" {
				return fmt.Errorf("sink %d: s3.bucket is required", i)
			}
			if strings.TrimSpace(s.S3.PrefixTemplate) == "" {
				return fmt.Errorf("sink %d: s3.prefix_template is required", i)
			}
			ft := strings.ToLower(strings.TrimSpace(s.S3.Format))
			if ft == "" {
				s.S3.Format = "parquet"
			} else if ft != "parquet" {
				return fmt.Errorf("sink %d: s3.format %q unsupported (only 'parquet' supported now)", i, s.S3.Format)
			}
			if s.S3.Batch == nil {
				s.S3.Batch = &S3Batch{}
			}
			if s.S3.Batch.MaxRecords == 0 {
				s.S3.Batch.MaxRecords = 500000
			}
			if s.S3.Batch.MaxBytes == 0 {
				s.S3.Batch.MaxBytes = 256 * 1024 * 1024
			}
			if s.S3.Batch.MaxAgeMS == 0 {
				s.S3.Batch.MaxAgeMS = 300_000
			}
			if s.S3.Batch.MaxRecords < 0 || s.S3.Batch.MaxBytes < 0 || s.S3.Batch.MaxAgeMS < 0 {
				return fmt.Errorf("sink %d: s3.batch values must be >= 0", i)
			}
			if s.S3.Parquet == nil {
				s.S3.Parquet = &Parquet{}
			}
			if strings.TrimSpace(s.S3.Parquet.Compression) == "" {
				s.S3.Parquet.Compression = "zstd"
			} else {
				cmp := strings.ToLower(strings.TrimSpace(s.S3.Parquet.Compression))
				if cmp != "zstd" && cmp != "snappy" && cmp != "gzip" {
					return fmt.Errorf("sink %d: s3.parquet.compression %q invalid", i, s.S3.Parquet.Compression)
				}
			}
			if s.S3.Parquet.RollWindowMS == 0 {
				s.S3.Parquet.RollWindowMS = 300_000
			}
			if s.S3.Parquet.RollMaxRecords == 0 {
				s.S3.Parquet.RollMaxRecords = 250_000
			}
			if s.S3.Parquet.RollWindowMS < 0 || s.S3.Parquet.RollMaxRecords < 0 {
				return fmt.Errorf("sink %d: s3.parquet roll_* must be >= 0", i)
			}
			if s.S3.AWS != nil {
				aws := s.S3.AWS
				if aws.EndpointURL != "" && !aws.UsePathStyle {
					aws.UsePathStyle = true
				}
				if aws.SessionName == "" && aws.RoleARN != "" {
					aws.SessionName = "core-session"
				}
				if aws.DurationMinutes == 0 && aws.RoleARN != "" {
					aws.DurationMinutes = 15
				}
			}

		case SinkTypeKafka:
			if s.Kafka == nil {
				return fmt.Errorf("sink %d: kafka block required for type 'kafka'", i)
			}
			k := s.Kafka
			if len(k.Brokers) == 0 {
				return fmt.Errorf("sink %d: kafka.brokers required", i)
			}
			if strings.TrimSpace(k.Topic) == "" {
				return fmt.Errorf("sink %d: kafka.topic required", i)
			}
			if strings.TrimSpace(k.Format) == "" {
				k.Format = "ndjson"
			} else {
				ff := strings.ToLower(strings.TrimSpace(k.Format))
				if ff != "ndjson" && ff != "json" {
					return fmt.Errorf("sink %d: kafka.format %q invalid (ndjson|json)", i, k.Format)
				}
			}
			if k.Batch == nil {
				k.Batch = &KafkaBatch{}
			}
			if k.Batch.MaxRecords == 0 {
				k.Batch.MaxRecords = 10000
			}
			if k.Batch.MaxBytesMB == 0 {
				k.Batch.MaxBytesMB = 16
			}
			if k.Batch.MaxAgeMS == 0 {
				k.Batch.MaxAgeMS = 800
			}
			if k.Batch.MaxRecords < 0 || k.Batch.MaxBytesMB < 0 || k.Batch.MaxAgeMS < 0 {
				return fmt.Errorf("sink %d: kafka.batch values must be >= 0", i)
			}
			if k.Writer == nil {
				k.Writer = &KafkaWriter{}
			}
			if k.Writer.BatchTimeoutMS == 0 {
				k.Writer.BatchTimeoutMS = 400
			}
			if strings.TrimSpace(k.Writer.Balancer) == "" {
				k.Writer.Balancer = "least_bytes"
			} else {
				switch strings.ToLower(strings.TrimSpace(k.Writer.Balancer)) {
				case "least_bytes", "round_robin", "hash":
				default:
					return fmt.Errorf("sink %d: kafka.writer.balancer %q invalid", i, k.Writer.Balancer)
				}
			}
			if strings.TrimSpace(k.ClientID) == "" {
				k.ClientID = "core-kafka-writer"
			}
			if k.Security != nil && k.Security.TLS != nil && k.Security.TLS.Enable {
				t := k.Security.TLS
				if len(t.CAFiles) == 0 {
					return fmt.Errorf("sink %d: kafka.security.tls.ca_files required when enable=true", i)
				}
				if strings.TrimSpace(t.ServerName) == "" && !t.InsecureSkipVerify {
					return fmt.Errorf("sink %d: kafka.security.tls.server_name required unless insecure_skip_tls_verify=true", i)
				}
				if (strings.TrimSpace(t.ClientCert) != "" && strings.TrimSpace(t.ClientKey) == "") ||
					(strings.TrimSpace(t.ClientKey) != "" && strings.TrimSpace(t.ClientCert) == "") {
					return fmt.Errorf("sink %d: kafka.security.tls client_cert and client_key must be provided together", i)
				}
			}
			if k.Security != nil && k.Security.SASL != nil {
				m := strings.ToUpper(strings.TrimSpace(k.Security.SASL.Mechanism))
				switch m {
				case "SCRAM-SHA-256", "SCRAM-SHA-512", "PLAIN":
					if k.Security.SASL.Username == "" || k.Security.SASL.Password == "" {
						return fmt.Errorf("sink %d: kafka.security.sasl username/password required", i)
					}
				case "":
				default:
					return fmt.Errorf("sink %d: kafka.security.sasl.mechanism %q invalid", i, k.Security.SASL.Mechanism)
				}
			}

		default:
			return fmt.Errorf("sink %d: unknown type %q", i, s.Type)
		}
	}

	return nil
}
