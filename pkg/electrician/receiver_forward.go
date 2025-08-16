package electrician

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joeydtaylor/electrician/pkg/builder"
)

// StartReceiverForwardFromEnv wires: ReceivingRelay[T] -> Wire[T]{transforms...} -> ForwardRelay[T].
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
func StartReceiverForwardFromEnv[T any](ctx context.Context, address string, buffer int, transforms ...func(T) (T, error)) (stop func(), err error) {
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("receiver: address required")
	}
	if buffer <= 0 {
		buffer = 1024
	}

	// logger shared across components
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

	// ---- Wire
	wire := builder.NewWire[T](
		ctx,
		builder.WireWithLogger[T](logger),
		builder.WireWithTransformer[T](composite),
	)

	// =======================
	// Forward hop (publisher)
	// =======================
	fwd, err := loadForwardEnv()
	if err != nil {
		return nil, err
	}

	perf := builder.NewPerformanceOptions(fwd.useSnappy, builder.COMPRESS_SNAPPY)
	sec := builder.NewSecurityOptions(fwd.useAESGCM, builder.ENCRYPTION_AES_GCM)
	tlsCli := builder.NewTlsClientConfig(
		fwd.useTLS, fwd.tlsCrt, fwd.tlsKey, fwd.tlsCA,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	var forwardStart func(context.Context) error
	var forwardStop func()

	if fwd.oauthEnabled {
		authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
		if fwd.jwks != "" {
			authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
				builder.NewForwardRelayOAuth2JWTOptions(fwd.issuer, fwd.jwks, splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")), fwd.scopes, 300),
			)
		}
		authHTTP := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS13,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: fwd.tlsInsecure, // dev only
				},
			},
		}

		// Preflight token warmup (non-fatal)
		preflightTimeout := parseDur(envOr("OAUTH_PREFLIGHT_TIMEOUT", "8s"))
		_ = preflightOAuthToken(ctx, authHTTP, fwd.issuer, fwd.clientID, fwd.clientSecret, fwd.scopes, preflightTimeout)

		ts := builder.NewForwardRelayRefreshingClientCredentialsSource(
			fwd.issuer, fwd.clientID, fwd.clientSecret, fwd.scopes, fwd.leeway, authHTTP,
		)

		f := builder.NewForwardRelay[T](
			ctx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](fwd.targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, fwd.aesKey),
			builder.ForwardRelayWithTLSConfig[T](tlsCli),
			builder.ForwardRelayWithStaticHeaders[T](fwd.staticHeaders),
			builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
			builder.ForwardRelayWithOAuthBearer[T](ts),
			builder.ForwardRelayWithInput(wire),
		)
		forwardStart, forwardStop = f.Start, f.Stop
	} else {
		f := builder.NewForwardRelay[T](
			ctx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](fwd.targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, fwd.aesKey),
			builder.ForwardRelayWithTLSConfig[T](tlsCli),
			builder.ForwardRelayWithStaticHeaders[T](fwd.staticHeaders),
			builder.ForwardRelayWithInput(wire),
		)
		forwardStart, forwardStop = f.Start, f.Stop
	}

	// ====================
	// Receive hop (server)
	// ====================
	rx, err := loadReceiverEnv()
	if err != nil {
		return nil, err
	}

	tlsSrv := builder.NewTlsServerConfig(
		rx.rxTLSEnable,
		rx.rxCrt, rx.rxKey, rx.rxCA, rx.rxName,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	var receiverStart func(context.Context) error
	var receiverStop func()

	switch {
	case rx.jwks != "" && rx.introspectURL != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			builder.NewReceivingRelayOAuth2JWTOptions(
				fwd.issuer,
				rx.jwks,
				splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")),
				fwd.scopes,
				300,
			),
			builder.NewReceivingRelayOAuth2IntrospectionOptions(
				rx.introspectURL,
				envOr("OAUTH_INTROSPECT_AUTH", "basic"),
				fwd.clientID,
				fwd.clientSecret,
				os.Getenv("OAUTH_INTROSPECT_BEARER"),
				300,
			),
		)
		auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

		r := builder.NewReceivingRelay[T](
			ctx,
			builder.ReceivingRelayWithAddress[T](address),
			builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
			builder.ReceivingRelayWithLogger[T](logger),
			builder.ReceivingRelayWithOutput(wire),
			builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
			builder.ReceivingRelayWithDecryptionKey[T](rx.decKey),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = r.Start, r.Stop

	case rx.jwks != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			builder.NewReceivingRelayOAuth2JWTOptions(
				fwd.issuer,
				rx.jwks,
				splitCSV(os.Getenv("OAUTH_REQUIRED_AUD")),
				fwd.scopes,
				300,
			),
			nil,
		)
		auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

		r := builder.NewReceivingRelay[T](
			ctx,
			builder.ReceivingRelayWithAddress[T](address),
			builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
			builder.ReceivingRelayWithLogger[T](logger),
			builder.ReceivingRelayWithOutput(wire),
			builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
			builder.ReceivingRelayWithDecryptionKey[T](rx.decKey),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = r.Start, r.Stop

	case rx.introspectURL != "":
		oauth := builder.NewReceivingRelayMergeOAuth2Options(
			nil,
			builder.NewReceivingRelayOAuth2IntrospectionOptions(
				rx.introspectURL,
				envOr("OAUTH_INTROSPECT_AUTH", "basic"),
				fwd.clientID,
				fwd.clientSecret,
				os.Getenv("OAUTH_INTROSPECT_BEARER"),
				300,
			),
		)
		auth := builder.NewReceivingRelayAuthenticationOptionsOAuth2(oauth)

		r := builder.NewReceivingRelay[T](
			ctx,
			builder.ReceivingRelayWithAddress[T](address),
			builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
			builder.ReceivingRelayWithLogger[T](logger),
			builder.ReceivingRelayWithOutput(wire),
			builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
			builder.ReceivingRelayWithDecryptionKey[T](rx.decKey),
			builder.ReceivingRelayWithAuthenticationOptions[T](auth),
		)
		receiverStart, receiverStop = r.Start, r.Stop

	default:
		// No OAuth on receiver
		r := builder.NewReceivingRelay[T](
			ctx,
			builder.ReceivingRelayWithAddress[T](address),
			builder.ReceivingRelayWithBufferSize[T](uint32(buffer)),
			builder.ReceivingRelayWithLogger[T](logger),
			builder.ReceivingRelayWithOutput(wire),
			builder.ReceivingRelayWithTLSConfig[T](tlsSrv),
			builder.ReceivingRelayWithDecryptionKey[T](rx.decKey),
		)
		receiverStart, receiverStop = r.Start, r.Stop
	}

	// Start: wire -> forward -> receiver
	if err := wire.Start(ctx); err != nil {
		return nil, err
	}
	if err := forwardStart(ctx); err != nil {
		return nil, err
	}
	if err := receiverStart(ctx); err != nil {
		return nil, err
	}

	// Stop in reverse
	return func() {
		receiverStop()
		forwardStop()
		wire.Stop()
	}, nil
}
