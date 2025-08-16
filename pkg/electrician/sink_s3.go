// pkg/electrician/sink_s3.go
package electrician

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// s3Env is pure-data config for S3 writer.
type s3Env struct {
	bucket             string
	region             string
	endpoint           string
	usePathStyle       bool
	roleARN            string
	sessionName        string
	durationMin        int
	accessKeyID        string
	secretAccessKey    string
	prefixTemplate     string
	orgID              string
	parquetCompression string // zstd|snappy|gzip
	rollWindowMS       int
	rollMaxRecords     int
	batchMaxRecords    int
	batchMaxBytes      int
	batchMaxAge        time.Duration
	sseType            string // "aws:kms" | "s3" | "aes256"
	kmsAliasArn        string
}

func loadS3Env() (*s3Env, error) {
	bucket := strings.TrimSpace(envOr("S3_BUCKET", ""))
	if bucket == "" {
		return nil, nil // disabled
	}
	cfg := &s3Env{
		bucket:             bucket,
		region:             envOr("S3_REGION", "us-east-1"),
		endpoint:           envOr("S3_ENDPOINT", "http://localhost:4566"),
		usePathStyle:       true, // LocalStack compat
		roleARN:            strings.TrimSpace(os.Getenv("AWS_ASSUME_ROLE_ARN")),
		sessionName:        envOr("AWS_SESSION_NAME", "electrician-writer"),
		durationMin:        envInt("AWS_SESSION_DURATION_MIN", 15),
		accessKeyID:        os.Getenv("AWS_ACCESS_KEY_ID"),
		secretAccessKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
		prefixTemplate:     envOr("S3_PREFIX_TEMPLATE", "debug/{yyyy}/{MM}/{dd}/{HH}/{mm}/"),
		orgID:              strings.TrimSpace(os.Getenv("ORG_ID")),
		parquetCompression: strings.ToLower(envOr("PARQUET_COMPRESSION", "zstd")),
		rollWindowMS:       envInt("ROLL_WINDOW_MS", 300_000),
		rollMaxRecords:     envInt("ROLL_MAX_RECORDS", 250_000),
		batchMaxRecords:    envInt("BATCH_MAX_RECORDS", 500_000),
		batchMaxBytes:      envInt("BATCH_MAX_BYTES_MB", 256) * (1 << 20),
		batchMaxAge:        envDurMs("BATCH_MAX_AGE_MS", 5*time.Minute),
		sseType:            strings.ToLower(envOr("S3_SSE_MODE", "aes256")),
		kmsAliasArn:        strings.TrimSpace(os.Getenv("S3_KMS_KEY_ARN")),
	}
	if cfg.orgID != "" {
		cfg.prefixTemplate = strings.ReplaceAll(cfg.prefixTemplate, "{org}", cfg.orgID)
	}
	// strconv referenced in original writer options; keep import path valid
	_ = strconv.IntSize
	return cfg, nil
}
