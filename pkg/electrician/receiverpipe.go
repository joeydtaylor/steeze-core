// pkg/electrician/receiverpipe.go
package electrician

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/joeydtaylor/electrician/pkg/builder"
)

// StartReceiverForwardFromEnv wires:
//
//	ReceivingRelay[T] -> Wire[T]{transforms...} -> { ForwardRelay[T]?, S3Writer[T]?, KafkaWriter[T]? }
//
// Forward env (same contract as NewBuilderRelayFromEnv):
//
//	ELECTRICIAN_TARGET, ELECTRICIAN_TLS_ENABLE, ELECTRICIAN_TLS_CLIENT_CRT, ELECTRICIAN_TLS_CLIENT_KEY, ELECTRICIAN_TLS_CA
//	ELECTRICIAN_TLS_INSECURE, ELECTRICIAN_COMPRESS, ELECTRICIAN_ENCRYPT, ELECTRICIAN_AES256_KEY_HEX
//	ELECTRICIAN_STATIC_HEADERS, OAUTH_ISSUER_BASE, OAUTH_JWKS_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_SCOPES, OAUTH_REFRESH_LEEWAY
//
// Receive env:
//
//	ELECTRICIAN_RX_TLS_ENABLE, ELECTRICIAN_RX_TLS_SERVER_CRT, ELECTRICIAN_RX_TLS_SERVER_KEY, ELECTRICIAN_RX_TLS_CA, ELECTRICIAN_RX_TLS_SERVER_NAME
//	OAUTH_JWKS_URL, OAUTH_ISSUER_BASE, OAUTH_REQUIRED_AUD, OAUTH_SCOPES,
//	OAUTH_INTROSPECT_URL, OAUTH_INTROSPECT_AUTH, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_INTROSPECT_BEARER
//
// S3 writer env:
//
//	S3_REGION, S3_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_ASSUME_ROLE_ARN
//	S3_BUCKET, S3_PREFIX_TEMPLATE, ORG_ID
//	S3_SSE_MODE, S3_KMS_KEY_ARN
//	PARQUET_COMPRESSION, ROLL_WINDOW_MS, ROLL_MAX_RECORDS, BATCH_MAX_RECORDS, BATCH_MAX_BYTES_MB, BATCH_MAX_AGE_MS
//
// Kafka writer env:
//
//	KAFKA_BROKERS=host:port[,host2:port2]   (required with KAFKA_TOPIC to enable)
//	KAFKA_TOPIC=feedback-demo
//	KAFKA_FORMAT=ndjson|json                (default ndjson)
//	KAFKA_KEY_TEMPLATE={customerId}         (optional)
//	KAFKA_HEADERS=k=v,k2=v2                 (optional)
//	KAFKA_BATCH_MAX_RECORDS=10000
//	KAFKA_BATCH_MAX_BYTES_MB=16
//	KAFKA_BATCH_MAX_AGE_MS=800
//	KAFKA_WRITER_BATCH_TIMEOUT_MS=400
//	KAFKA_CLIENT_ID=exodus-kafka-writer
//	KAFKA_TLS_ENABLE=true
//	KAFKA_TLS_CA_FILES=./tls/ca.crt,../tls/ca.crt,../../tls/ca.crt
//	KAFKA_TLS_SERVER_NAME=localhost
//	KAFKA_TLS_CLIENT_CERT=/app/etc/keys/tls/client.crt
//	KAFKA_TLS_CLIENT_KEY=/app/etc/keys/tls/client.key
//	KAFKA_TLS_INSECURE=false
//	KAFKA_SASL_MECHANISM=SCRAM-SHA-256|SCRAM-SHA-512
//	KAFKA_SASL_USERNAME=app
//	KAFKA_SASL_PASSWORD=app-secret
func StartReceiverForwardFromEnv[T any](ctx context.Context, address string, buffer int, transforms ...func(T) (T, error)) (stop func(), err error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("receiver: address required")
	}
	if buffer <= 0 {
		buffer = 1024
	}

	logger := builder.NewLogger(builder.LoggerWithDevelopment(true))

	// Composite transformer
	composite := func(v T) (T, error) {
		cur := v
		for _, fn := range transforms {
			var err error
			cur, err = fn(cur)
			if err != nil {
				return cur, err
			}
		}
		return cur, nil
	}

	// ---- Wire (shared by forward + all sinks)
	wire := builder.NewWire[T](
		ctx,
		builder.WireWithLogger[T](logger),
		builder.WireWithTransformer[T](composite),
	)

	// =======================
	// Forward hop (publisher)
	// =======================
	targets := splitCSV(os.Getenv("ELECTRICIAN_TARGET"))
	useTLS := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_ENABLE"), "true")
	tlsCrt := envOr("ELECTRICIAN_TLS_CLIENT_CRT", "keys/tls/client.crt")
	tlsKey := envOr("ELECTRICIAN_TLS_CLIENT_KEY", "keys/tls/client.key")
	tlsCA := envOr("ELECTRICIAN_TLS_CA", "keys/tls/ca.crt")
	tlsInsecure := strings.EqualFold(os.Getenv("ELECTRICIAN_TLS_INSECURE"), "true")

	useSnappy := strings.EqualFold(os.Getenv("ELECTRICIAN_COMPRESS"), "snappy")
	useAESGCM := strings.EqualFold(os.Getenv("ELECTRICIAN_ENCRYPT"), "aesgcm")
	var fwdAES string
	if useAESGCM {
		k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX"))
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return nil, errors.New("forward: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		fwdAES = string(raw)
	}

	staticHeaders := parseKV(os.Getenv("ELECTRICIAN_STATIC_HEADERS"))

	issuer := strings.TrimSpace(os.Getenv("OAUTH_ISSUER_BASE"))
	jwksURL := strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
	clientID := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_CLIENT_SECRET"))
	scopes := splitCSV(os.Getenv("OAUTH_SCOPES"))
	leeway := parseDur(envOr("OAUTH_REFRESH_LEEWAY", "20s"))
	oauthEnabled := issuer != "" && clientID != "" && clientSecret != ""

	perf := builder.NewPerformanceOptions(useSnappy, builder.COMPRESS_SNAPPY)
	sec := builder.NewSecurityOptions(useAESGCM, builder.ENCRYPTION_AES_GCM)
	tlsCli := builder.NewTlsClientConfig(useTLS, tlsCrt, tlsKey, tlsCA, tls.VersionTLS13, tls.VersionTLS13)

	var forwardStart func(context.Context) error
	var forwardStop func()
	if len(targets) > 0 {
		if oauthEnabled {
			authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
			if jwksURL != "" {
				authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
					builder.NewForwardRelayOAuth2JWTOptions(issuer, jwksURL, splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")), scopes, 300),
				)
			}
			authHTTP := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion:         tls.VersionTLS13,
						MaxVersion:         tls.VersionTLS13,
						InsecureSkipVerify: tlsInsecure, // dev only
					},
				},
			}
			// Best-effort token preflight
			preflightTimeout := parseDur(envOr("OAUTH_PREFLIGHT_TIMEOUT", "8s"))
			_ = preflightOAuthToken(ctx, authHTTP, issuer, clientID, clientSecret, scopes, preflightTimeout)

			ts := builder.NewForwardRelayRefreshingClientCredentialsSource(issuer, clientID, clientSecret, scopes, leeway, authHTTP)

			f := builder.NewForwardRelay[T](
				ctx,
				builder.ForwardRelayWithLogger[T](logger),
				builder.ForwardRelayWithTarget[T](targets...),
				builder.ForwardRelayWithPerformanceOptions[T](perf),
				builder.ForwardRelayWithSecurityOptions[T](sec, fwdAES),
				builder.ForwardRelayWithTLSConfig[T](tlsCli),
				builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
				builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
				builder.ForwardRelayWithOAuthBearer[T](ts),
				builder.ForwardRelayWithInput(wire),
			)
			forwardStart, forwardStop = f.Start, f.Stop
		} else {
			f := builder.NewForwardRelay[T](
				ctx,
				builder.ForwardRelayWithLogger[T](logger),
				builder.ForwardRelayWithTarget[T](targets...),
				builder.ForwardRelayWithPerformanceOptions[T](perf),
				builder.ForwardRelayWithSecurityOptions[T](sec, fwdAES),
				builder.ForwardRelayWithTLSConfig[T](tlsCli),
				builder.ForwardRelayWithStaticHeaders[T](staticHeaders),
				builder.ForwardRelayWithInput(wire),
			)
			forwardStart, forwardStop = f.Start, f.Stop
		}
	} else {
		forwardStart = func(context.Context) error { return nil }
		forwardStop = func() {}
	}

	// ====================
	// Receive hop (server)
	// ====================
	rxTLSEnable := strings.EqualFold(os.Getenv("ELECTRICIAN_RX_TLS_ENABLE"), "true")
	rxCrt := envOr("ELECTRICIAN_RX_TLS_SERVER_CRT", "keys/tls/server.crt")
	rxKey := envOr("ELECTRICIAN_RX_TLS_SERVER_KEY", "keys/tls/server.key")
	rxCA := envOr("ELECTRICIAN_RX_TLS_CA", "keys/tls/ca.crt")
	rxName := os.Getenv("ELECTRICIAN_RX_TLS_SERVER_NAME")

	tlsSrv := builder.NewTlsServerConfig(
		rxTLSEnable,
		rxCrt, rxKey, rxCA, rxName,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	decKey := ""
	if k := strings.TrimSpace(os.Getenv("ELECTRICIAN_AES256_KEY_HEX")); k != "" {
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != 32 {
			return nil, errors.New("receiver: ELECTRICIAN_AES256_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		decKey = string(raw)
	}

	// Receiver OAuth2
	var receiverStart func(context.Context) error
	var receiverStop func()
	{
		jwks := strings.TrimSpace(os.Getenv("OAUTH_JWKS_URL"))
		introspectURL := strings.TrimSpace(os.Getenv("OAUTH_INTROSPECT_URL"))

		switch {
		case jwks != "" && introspectURL != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				builder.NewReceivingRelayOAuth2JWTOptions(
					issuer, jwks, splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")), scopes, 300,
				),
				builder.NewReceivingRelayOAuth2IntrospectionOptions(
					introspectURL, envOr("OAUTH_INTROSPECT_AUTH", "basic"),
					clientID, clientSecret, os.Getenv("OAUTH_INTROSPECT_BEARER"), 300,
				),
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)
			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		case jwks != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				builder.NewReceivingRelayOAuth2JWTOptions(
					issuer, jwks, splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")), scopes, 300,
				),
				nil,
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)
			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		case introspectURL != "":
			oauth := builder.NewReceivingRelayMergeOAuth2Options(
				nil,
				builder.NewReceivingRelayOAuth2IntrospectionOptions(
					introspectURL, envOr("OAUTH_INTROSPECT_AUTH", "basic"),
					clientID, clientSecret, os.Getenv("OAUTH_INTROSPECT_BEARER"), 300,
				),
			)
			auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)
			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
				builder.ReceivingRelayWithAuthenticationOptions[T](auth),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop

		default:
			// No OAuth on receiver
			rx := builder.NewReceivingRelay[T](
				ctx,
				builder.ReceivingRelayWithAddress[T](address),
				builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
				builder.ReceivingRelayWithLogger[T](logger),
				builder.ReceivingRelayWithOutput(wire),
				builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
				builder.ReceivingRelayWithDecryptionKey[T](decKey),
			)
			receiverStart, receiverStop = rx.Start, rx.Stop
		}
	}

	// ====================
	// Sinks (fan-out wire)
	// ====================

	// Fan-out controller
	type writerCtl interface {
		StartWriter(context.Context) error
		Stop()
	}
	var writers []writerCtl

	// ---- S3 writer (enabled when bucket present)
	bucket := strings.TrimSpace(envOr("S3_BUCKET", ""))
	if bucket != "" {
		// Client
		awsRegion := envOr("S3_REGION", "us-east-1")
		endpoint := envOr("S3_ENDPOINT", "http://localhost:4566")
		usePathStyle := true // LocalStack compat; can add env if needed

		roleARN := strings.TrimSpace(os.Getenv("AWS_ASSUME_ROLE_ARN"))
		sessionName := envOr("AWS_SESSION_NAME", "electrician-writer")
		durationMin := envInt("AWS_SESSION_DURATION_MIN", 15)
		ak := os.Getenv("AWS_ACCESS_KEY_ID")
		sk := os.Getenv("AWS_SECRET_ACCESS_KEY")

		cli, err := builder.NewS3ClientAssumeRole(
			ctx,
			awsRegion,
			roleARN,
			sessionName,
			time.Duration(durationMin)*time.Minute,
			"", // external ID
			aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(ak, sk, "")),
			endpoint,
			usePathStyle,
		)
		if err != nil {
			return nil, err
		}

		prefixTemplate := envOr("S3_PREFIX_TEMPLATE", "debug/{yyyy}/{MM}/{dd}/{HH}/{mm}/")
		orgID := strings.TrimSpace(os.Getenv("ORG_ID"))
		if orgID != "" {
			prefixTemplate = strings.ReplaceAll(prefixTemplate, "{org}", orgID)
		}
		parquetCompression := strings.ToLower(envOr("PARQUET_COMPRESSION", "zstd")) // zstd|snappy|gzip
		rollWindow := envInt("ROLL_WINDOW_MS", 300_000)
		rollMaxRecords := envInt("ROLL_MAX_RECORDS", 250_000)
		batchMaxRecords := envInt("BATCH_MAX_RECORDS", 500_000)
		batchMaxBytes := envInt("BATCH_MAX_BYTES_MB", 256) * (1 << 20)
		batchMaxAge := envDurMs("BATCH_MAX_AGE_MS", 5*time.Minute)

		sseType := strings.ToLower(envOr("S3_SSE_MODE", "aes256")) // "aws:kms" | "s3" | "aes256"
		kmsAliasArn := strings.TrimSpace(os.Getenv("S3_KMS_KEY_ARN"))

		// Adapter
		s3ad := builder.NewS3ClientAdapter[T](
			ctx,
			builder.S3ClientAdapterWithClientAndBucket[T](cli, bucket),
			builder.S3ClientAdapterWithFormat[T]("parquet", ""),
			builder.S3ClientAdapterWithWriterPrefixTemplate[T](prefixTemplate),
			builder.S3ClientAdapterWithBatchSettings[T](batchMaxRecords, batchMaxBytes, batchMaxAge),
			builder.S3ClientAdapterWithWriterFormatOptions[T](map[string]string{
				"parquet_compression": parquetCompression,
				"roll_window_ms":      strconv.Itoa(rollWindow),
				"roll_max_records":    strconv.Itoa(rollMaxRecords),
			}),
			builder.S3ClientAdapterWithSSE[T](sseType, kmsAliasArn),
			builder.S3ClientAdapterWithWire[T](wire),
			builder.S3ClientAdapterWithLogger[T](logger),
		)

		if ws, ok := any(s3ad).(writerCtl); ok {
			writers = append(writers, ws)
		} else {
			return nil, errors.New("s3 adapter missing StartWriter/Stop")
		}
	}

	// ---- Kafka writer (enabled when brokers+topic set)
	kBrokers := splitCSV(os.Getenv("KAFKA_BROKERS"))
	kTopic := strings.TrimSpace(os.Getenv("KAFKA_TOPIC"))
	if len(kBrokers) > 0 && kTopic != "" {
		// Security
		var kTLS *tls.Config
		if strings.EqualFold(os.Getenv("KAFKA_TLS_ENABLE"), "true") || os.Getenv("KAFKA_TLS_CA_FILES") != "" {
			caFiles := splitCSV(envOr("KAFKA_TLS_CA_FILES", "./tls/ca.crt,../tls/ca.crt,../../tls/ca.crt"))
			serverName := envOr("KAFKA_TLS_SERVER_NAME", "localhost")
			var err error
			kTLS, err = builder.TLSFromCAFilesStrict(caFiles, serverName)
			if err != nil {
				return nil, err
			}
			// Optional mTLS: present client cert if provided
			certPath := strings.TrimSpace(os.Getenv("KAFKA_TLS_CLIENT_CERT"))
			keyPath := strings.TrimSpace(os.Getenv("KAFKA_TLS_CLIENT_KEY"))
			if certPath != "" && keyPath != "" {
				cert, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					return nil, err
				}
				kTLS.Certificates = []tls.Certificate{cert}
			}
			if strings.EqualFold(os.Getenv("KAFKA_TLS_INSECURE"), "true") {
				kTLS.InsecureSkipVerify = true // dev only
			}
			if kTLS.MinVersion == 0 {
				kTLS.MinVersion = tls.VersionTLS12
			}
		}

		secOpts := []builder.KafkaSecurityOption{
			builder.WithClientID(envOr("KAFKA_CLIENT_ID", "exodus-kafka-writer")),
		}
		if kTLS != nil {
			secOpts = append(secOpts, builder.WithTLS(kTLS))
		}

		if mechName := strings.ToUpper(strings.TrimSpace(os.Getenv("KAFKA_SASL_MECHANISM"))); mechName != "" {
			user := strings.TrimSpace(os.Getenv("KAFKA_SASL_USERNAME"))
			pass := strings.TrimSpace(os.Getenv("KAFKA_SASL_PASSWORD"))
			m, err := builder.SASLSCRAM(user, pass, mechName) // returns sasl.Mechanism
			if err != nil {
				return nil, err
			}
			secOpts = append(secOpts, builder.WithSASL(m))
		}

		sec := builder.NewKafkaSecurity(secOpts...)

		// kafka-go writer (least-bytes + batch timeout)
		kBatchTimeout := envInt("KAFKA_WRITER_BATCH_TIMEOUT_MS", 400)
		kw := builder.NewKafkaGoWriterWithSecurity(
			kBrokers,
			kTopic,
			sec,
			builder.KafkaGoWriterWithLeastBytes(),
			builder.KafkaGoWriterWithBatchTimeout(time.Duration(kBatchTimeout)*time.Millisecond),
		)

		// Adapter
		kFormat := strings.ToLower(envOr("KAFKA_FORMAT", "ndjson")) // ndjson|json
		if kFormat != "ndjson" && kFormat != "json" {
			return nil, errors.New("kafka: KAFKA_FORMAT must be ndjson or json")
		}
		kMaxRecords := coalesceInt(os.Getenv("KAFKA_BATCH_MAX_RECORDS"), 10000)
		kMaxBytes := coalesceInt(os.Getenv("KAFKA_BATCH_MAX_BYTES_MB"), 16) * (1 << 20)
		kMaxAge := coalesceDurMs(os.Getenv("KAFKA_BATCH_MAX_AGE_MS"), 800*time.Millisecond)
		keyTpl := os.Getenv("KAFKA_KEY_TEMPLATE") // optional
		hdrs := parseKV(os.Getenv("KAFKA_HEADERS"))

		kad := builder.NewKafkaClientAdapter[T](
			ctx,
			builder.KafkaClientAdapterWithKafkaGoWriter[T](kw),
			builder.KafkaClientAdapterWithWriterTopic[T](kTopic),
			builder.KafkaClientAdapterWithWriterFormat[T](kFormat, ""),
			builder.KafkaClientAdapterWithWriterBatchSettings[T](kMaxRecords, kMaxBytes, kMaxAge),
			builder.KafkaClientAdapterWithWriterKeyTemplate[T](keyTpl),
			builder.KafkaClientAdapterWithWriterHeaderTemplates[T](hdrs),
			builder.KafkaClientAdapterWithWire[T](wire),
			builder.KafkaClientAdapterWithLogger[T](logger),
		)

		if kwc, ok := any(kad).(writerCtl); ok {
			writers = append(writers, kwc)
		} else {
			return nil, errors.New("kafka adapter missing StartWriter/Stop")
		}
	}

	// =========
	// Start all
	// =========
	if err := wire.Start(ctx); err != nil {
		return nil, err
	}
	if err := forwardStart(ctx); err != nil {
		return nil, err
	}
	if err := receiverStart(ctx); err != nil {
		return nil, err
	}
	for _, w := range writers {
		if err := w.StartWriter(ctx); err != nil {
			return nil, err
		}
	}

	// Stop in reverse
	return func() {
		for i := len(writers) - 1; i >= 0; i-- {
			writers[i].Stop()
		}
		receiverStop()
		forwardStop()
		wire.Stop()
	}, nil
}

// -----------------------
// Helpers (preflight etc)
// -----------------------

func preflightOAuthToken(ctx context.Context, hc *http.Client, issuer, clientID, clientSecret string, scopes []string, total time.Duration) error {
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	tokenURL := strings.TrimRight(issuer, "/") + "/api/auth/oauth/token"
	if _, err := url.Parse(tokenURL); err != nil {
		return nil
	}

	deadline := time.Now().Add(total)
	sleep := 250 * time.Millisecond

	for {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ctx.Err()
		}
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		if len(scopes) > 0 {
			form.Set("scope", strings.Join(scopes, " "))
		}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := hc.Do(req)
		cancel()

		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		time.Sleep(sleep)
		if sleep < 2*time.Second {
			sleep *= 2
		}
	}
}

// --- tiny env helpers (local to this file) ---

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurMs(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return def
}

// coalesce helpers for KAFKA_* that prefer specific vars over shared ones
func coalesceInt(v string, def int) int {
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func coalesceDurMs(v string, def time.Duration) time.Duration {
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return def
}
