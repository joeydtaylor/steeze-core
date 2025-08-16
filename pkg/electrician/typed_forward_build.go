// pkg/electrician/typed_forward_build.go
package electrician

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/joeydtaylor/electrician/pkg/builder"
)

// buildTypedForwardSubmitter constructs the Wire[T] + ForwardRelay[T] from env and
// returns a submitter func(ctx, any) error matching existing semantics.
func buildTypedForwardSubmitter[T any](ctx context.Context, typeName string) (func(context.Context, any) error, error) {
	cfg, err := loadForwardEnv()
	if err != nil {
		return nil, err
	}
	// If no targets, be a no-op so router can still run.
	if len(cfg.targets) == 0 {
		return func(context.Context, any) error { return nil }, nil
	}

	logger := builder.NewLogger(builder.LoggerWithDevelopment(true))
	buildCtx := ctx
	if buildCtx == nil {
		buildCtx = context.Background()
	}

	// Wire[T]
	wire := builder.NewWire[T](buildCtx, builder.WireWithLogger[T](logger))

	// Options
	perf := builder.NewPerformanceOptions(cfg.useSnappy, builder.COMPRESS_SNAPPY)
	sec := builder.NewSecurityOptions(cfg.useAESGCM, builder.ENCRYPTION_AES_GCM)
	tlsCfg := builder.NewTlsClientConfig(
		cfg.useTLS, cfg.tlsCrt, cfg.tlsKey, cfg.tlsCA,
		tls.VersionTLS13, tls.VersionTLS13,
	)

	// Relay
	var start func(context.Context) error
	if cfg.oauthEnabled {
		authOpts := builder.NewForwardRelayAuthenticationOptionsOAuth2(nil)
		if cfg.jwksURL != "" {
			// Typed publisher keeps empty required-aud to match prior behavior.
			authOpts = builder.NewForwardRelayAuthenticationOptionsOAuth2(
				builder.NewForwardRelayOAuth2JWTOptions(cfg.issuer, cfg.jwksURL, []string{}, cfg.scopes, 300),
			)
		}
		authHTTP := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS13,
					MaxVersion:         tls.VersionTLS13,
					InsecureSkipVerify: cfg.tlsInsecure, // dev only
				},
			},
		}
		ts := builder.NewForwardRelayRefreshingClientCredentialsSource(
			cfg.issuer, cfg.clientID, cfg.clientSecret, cfg.scopes, cfg.leeway, authHTTP,
		)

		relay := builder.NewForwardRelay[T](
			buildCtx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](cfg.targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, string(cfg.aesKey)),
			builder.ForwardRelayWithTLSConfig[T](tlsCfg),
			builder.ForwardRelayWithStaticHeaders[T](cfg.staticHeaders),
			builder.ForwardRelayWithAuthenticationOptions[T](authOpts),
			builder.ForwardRelayWithOAuthBearer[T](ts),
			builder.ForwardRelayWithInput(wire),
		)
		start = relay.Start
	} else {
		relay := builder.NewForwardRelay[T](
			buildCtx,
			builder.ForwardRelayWithLogger[T](logger),
			builder.ForwardRelayWithTarget[T](cfg.targets...),
			builder.ForwardRelayWithPerformanceOptions[T](perf),
			builder.ForwardRelayWithSecurityOptions[T](sec, string(cfg.aesKey)),
			builder.ForwardRelayWithTLSConfig[T](tlsCfg),
			builder.ForwardRelayWithStaticHeaders[T](cfg.staticHeaders),
			builder.ForwardRelayWithInput(wire),
		)
		start = relay.Start
	}

	if err := wire.Start(buildCtx); err != nil {
		return nil, fmt.Errorf("wire start: %w", err)
	}
	if err := start(buildCtx); err != nil {
		return nil, fmt.Errorf("relay start: %w", err)
	}

	// Submitter; allow []byte convenience
	return func(ctx context.Context, v any) error {
		if tv, ok := v.(T); ok {
			return wire.Submit(ctx, tv)
		}
		if b, ok := v.([]byte); ok {
			var tmp T
			if err := json.Unmarshal(b, &tmp); err != nil {
				return fmt.Errorf("decode %q: %w", typeName, err)
			}
			return wire.Submit(ctx, tmp)
		}
		return fmt.Errorf("typed submit %q: unexpected value type", typeName)
	}, nil
}
