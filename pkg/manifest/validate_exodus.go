package manifest

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Exodus semantics (sinks + wires)
func (c *Config) validateExodus() error {
	// Routes optional; if present, validate
	if err := c.validateRoutes(); err != nil {
		return err
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
