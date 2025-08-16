package manifest

// S3 sink configuration.
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
