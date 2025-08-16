// pkg/electrician/receiver_pipeline.go
package electrician

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/joeydtaylor/electrician/pkg/builder"
)

// writerCtl matches the adapters' StartWriter/Stop surface (local to this file).
type writerCtl interface {
	StartWriter(context.Context) error
	Stop()
}

func StartReceiverForwardFromEnv[T any](
	ctx context.Context,
	address string,
	buffer int,
	transforms ...func(T) (T, error),
) (stop func(), err error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("receiver: address required")
	}
	if buffer <= 0 {
		buffer = 1024
	}

	logger := builder.NewLogger(builder.LoggerWithDevelopment(true))

	// Composite transformer preserved.
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

	// Shared wire.
	wire := builder.NewWire[T](
		ctx,
		builder.WireWithLogger[T](logger),
		builder.WireWithTransformer[T](composite),
	)

	// -------- Forward hop (from env -> builder)
	fwdCfg, err := loadForwardEnv()
	if err != nil {
		return nil, err
	}
	var forwardStart func(context.Context) error
	var forwardStop func()

	if len(fwdCfg.targets) == 0 {
		forwardStart = func(context.Context) error { return nil }
		forwardStop = func() {}
	} else {
		perf := builder.NewPerformanceOptions(fwdCfg.useSnappy, builder.COMPRESS_SNAPPY)
		sec := builder.NewSecurityOptions(fwdCfg.useAESGCM, builder.ENCRYPTION_AES_GCM)
		tlsCli := builder.NewTlsClientConfig(
			fwdCfg.useTLS, fwdCfg.tlsCrt, fwdCfg.tlsKey, fwdCfg.tlsCA,
			tls.VersionTLS13, tls.VersionTLS13,
		)

		if fwdCfg.oauthEnabled {
			authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
			if fwdCfg.jwksURL != "" {
				authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
					builder.NewForwardRelayOAuth2JWTOptions(fwdCfg.issuer, fwdCfg.jwksURL, fwdCfg.requiredAud, fwdCfg.scopes, 300),
				)
			}
			authHTTP := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion:         tls.VersionTLS13,
						MaxVersion:         tls.VersionTLS13,
						InsecureSkipVerify: fwdCfg.tlsInsecure, // dev only
					},
				},
			}
			_ = preflightOAuthToken(ctx, authHTTP, fwdCfg.issuer, fwdCfg.clientID, fwdCfg.clientSecret, fwdCfg.scopes, fwdCfg.preflightTimeout)

			ts := builder.NewForwardRelayRefreshingClientCredentialsSource(
				fwdCfg.issuer, fwdCfg.clientID, fwdCfg.clientSecret, fwdCfg.scopes, fwdCfg.leeway, authHTTP,
			)

			f := builder.NewForwardRelay[T](
				ctx,
				builder.ForwardRelayWithLogger[T](logger),
				builder.ForwardRelayWithTarget[T](fwdCfg.targets...),
				builder.ForwardRelayWithPerformanceOptions[T](perf),
				builder.ForwardRelayWithSecurityOptions[T](sec, string(fwdCfg.aesKey)),
				builder.ForwardRelayWithTLSConfig[T](tlsCli),
				builder.ForwardRelayWithStaticHeaders[T](fwdCfg.staticHeaders),
				builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
				builder.ForwardRelayWithOAuthBearer[T](ts),
				builder.ForwardRelayWithInput(wire),
			)
			forwardStart, forwardStop = f.Start, f.Stop
		} else {
			f := builder.NewForwardRelay[T](
				ctx,
				builder.ForwardRelayWithLogger[T](logger),
				builder.ForwardRelayWithTarget[T](fwdCfg.targets...),
				builder.ForwardRelayWithPerformanceOptions[T](perf),
				builder.ForwardRelayWithSecurityOptions[T](sec, string(fwdCfg.aesKey)),
				builder.ForwardRelayWithTLSConfig[T](tlsCli),
				builder.ForwardRelayWithStaticHeaders[T](fwdCfg.staticHeaders),
				builder.ForwardRelayWithInput(wire),
			)
			forwardStart, forwardStop = f.Start, f.Stop
		}
	}

	// -------- Receiver hop (from env -> builder)
	rxCfg, err := loadReceiverEnv()
	if err != nil {
		return nil, err
	}
	tlsSrv := builder.NewTlsServerConfig(
		rxCfg.rxTLSEnable,
		rxCfg.rxCrt, rxCfg.rxKey, rxCfg.rxCA, rxCfg.rxName,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	var receiverStart func(context.Context) error
	var receiverStop func()
	switch {
	case rxCfg.jwks != "" && rxCfg.introspectURL != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			builder.NewReceivingRelayOAuth2JWTOptions(
				rxCfg.issuer, rxCfg.jwks, rxCfg.requiredAud, rxCfg.scopes, 300,
			),
			builder.NewReceivingRelayOAuth2IntrospectionOptions(
				rxCfg.introspectURL, rxCfg.introspectAuth,
				rxCfg.clientID, rxCfg.clientSecret, rxCfg.bearer, 300,
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
			builder.ReceivingRelayWithDecryptionKey[T](string(rxCfg.decKey)),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = rx.Start, rx.Stop

	case rxCfg.jwks != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			builder.NewReceivingRelayOAuth2JWTOptions(
				rxCfg.issuer, rxCfg.jwks, rxCfg.requiredAud, rxCfg.scopes, 300,
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
			builder.ReceivingRelayWithDecryptionKey[T](string(rxCfg.decKey)),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = rx.Start, rx.Stop

	case rxCfg.introspectURL != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			nil,
			builder.NewReceivingRelayOAuth2IntrospectionOptions(
				rxCfg.introspectURL, rxCfg.introspectAuth,
				rxCfg.clientID, rxCfg.clientSecret, rxCfg.bearer, 300,
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
			builder.ReceivingRelayWithDecryptionKey[T](string(rxCfg.decKey)),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = rx.Start, rx.Stop

	default:
		rx := builder.NewReceivingRelay[T](
			ctx,
			builder.ReceivingRelayWithAddress[T](address),
			builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
			builder.ReceivingRelayWithLogger[T](logger),
			builder.ReceivingRelayWithOutput(wire),
			builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
			builder.ReceivingRelayWithDecryptionKey[T](string(rxCfg.decKey)),
		)
		receiverStart, receiverStop = rx.Start, rx.Stop
	}

	// -------- Sinks (S3 then Kafka)
	s3Cfg, kCfg, err := loadSinksEnv()
	if err != nil {
		return nil, err
	}
	var writers []writerCtl

	if s3Cfg != nil {
		cli, err := builder.NewS3ClientAssumeRole(
			ctx,
			s3Cfg.region,
			s3Cfg.roleARN,
			s3Cfg.sessionName,
			time.Duration(s3Cfg.durationMin)*time.Minute,
			"", // external ID
			aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s3Cfg.accessKeyID, s3Cfg.secretAccessKey, "")),
			s3Cfg.endpoint,
			s3Cfg.usePathStyle,
		)
		if err != nil {
			return nil, err
		}

		s3ad := builder.NewS3ClientAdapter[T](
			ctx,
			builder.S3ClientAdapterWithClientAndBucket[T](cli, s3Cfg.bucket),
			builder.S3ClientAdapterWithFormat[T]("parquet", ""),
			builder.S3ClientAdapterWithWriterPrefixTemplate[T](s3Cfg.prefixTemplate),
			builder.S3ClientAdapterWithBatchSettings[T](s3Cfg.batchMaxRecords, s3Cfg.batchMaxBytes, s3Cfg.batchMaxAge),
			builder.S3ClientAdapterWithWriterFormatOptions[T](map[string]string{
				"parquet_compression": s3Cfg.parquetCompression,
				"roll_window_ms":      strconv.Itoa(s3Cfg.rollWindowMS),   // <-- fix
				"roll_max_records":    strconv.Itoa(s3Cfg.rollMaxRecords), // <-- fix
			}),
			builder.S3ClientAdapterWithSSE[T](s3Cfg.sseType, s3Cfg.kmsAliasArn),
			builder.S3ClientAdapterWithWire[T](wire),
			builder.S3ClientAdapterWithLogger[T](logger),
		)

		if ws, ok := any(s3ad).(writerCtl); ok {
			writers = append(writers, ws)
		} else {
			return nil, errors.New("s3 adapter missing StartWriter/Stop")
		}
	}

	if kCfg != nil {
		var kTLS *tls.Config
		if kCfg.tlsEnable {
			var err error
			kTLS, err = builder.TLSFromCAFilesStrict(kCfg.caFiles, kCfg.serverName)
			if err != nil {
				return nil, err
			}
			if kCfg.clientCert != "" && kCfg.clientKey != "" {
				cert, err := tls.LoadX509KeyPair(kCfg.clientCert, kCfg.clientKey)
				if err != nil {
					return nil, err
				}
				kTLS.Certificates = []tls.Certificate{cert}
			}
			if kCfg.tlsInsecure {
				kTLS.InsecureSkipVerify = true // dev only
			}
			if kTLS.MinVersion == 0 {
				kTLS.MinVersion = tls.VersionTLS12
			}
		}

		secOpts := []builder.KafkaSecurityOption{builder.WithClientID(kCfg.clientID)}
		if kTLS != nil {
			secOpts = append(secOpts, builder.WithTLS(kTLS))
		}
		if kCfg.saslMechanism != "" {
			m, err := builder.SASLSCRAM(kCfg.saslUsername, kCfg.saslPassword, kCfg.saslMechanism)
			if err != nil {
				return nil, err
			}
			secOpts = append(secOpts, builder.WithSASL(m))
		}
		sec := builder.NewKafkaSecurity(secOpts...)

		kw := builder.NewKafkaGoWriterWithSecurity(
			kCfg.brokers,
			kCfg.topic,
			sec,
			builder.KafkaGoWriterWithLeastBytes(),
			builder.KafkaGoWriterWithBatchTimeout(time.Duration(kCfg.writerTimeoutMS)*time.Millisecond),
		)

		kad := builder.NewKafkaClientAdapter[T](
			ctx,
			builder.KafkaClientAdapterWithKafkaGoWriter[T](kw),
			builder.KafkaClientAdapterWithWriterTopic[T](kCfg.topic),
			builder.KafkaClientAdapterWithWriterFormat[T](kCfg.format, ""),
			builder.KafkaClientAdapterWithWriterBatchSettings[T](kCfg.maxRecords, kCfg.maxBytes, kCfg.maxAge),
			builder.KafkaClientAdapterWithWriterKeyTemplate[T](kCfg.keyTemplate),
			builder.KafkaClientAdapterWithWriterHeaderTemplates[T](kCfg.headers),
			builder.KafkaClientAdapterWithWire[T](wire),
			builder.KafkaClientAdapterWithLogger[T](logger),
		)
		if kwc, ok := any(kad).(writerCtl); ok {
			writers = append(writers, kwc)
		} else {
			return nil, errors.New("kafka adapter missing StartWriter/Stop")
		}
	}

	// Start all.
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

	// Stop in reverse.
	return func() {
		for i := len(writers) - 1; i >= 0; i-- {
			writers[i].Stop()
		}
		receiverStop()
		forwardStop()
		wire.Stop()
	}, nil
}
