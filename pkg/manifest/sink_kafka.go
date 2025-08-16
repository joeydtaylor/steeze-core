package manifest

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
