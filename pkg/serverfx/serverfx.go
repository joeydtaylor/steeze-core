package serverfx

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/joeydtaylor/steeze-core/pkg/core"
	"github.com/joeydtaylor/steeze-core/pkg/electrician"
	"github.com/joeydtaylor/steeze-core/pkg/manifest"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/logger"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/metrics"
	"github.com/joeydtaylor/steeze-core/pkg/transport/httpx"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Options allow per-service env keys/defaults without code duplication.
type Options struct {
	Service         string // "hermes", "exodus", etc.
	ManifestEnv     string // e.g. "HERMES_MANIFEST" / "EXODUS_MANIFEST"
	DefaultManifest string // e.g. "manifest.toml"
	ListenAddrEnv   string // e.g. "SERVER_LISTEN_ADDRESS"
	DefaultListen   string // e.g. ":4000"
	TLSCertEnv      string // e.g. "SSL_SERVER_CERTIFICATE"
	TLSKeyEnv       string // e.g. "SSL_SERVER_KEY"
}

// ---- electrician.RelayClient -> core.RelayClient adapter ----

type relayAdapter struct {
	inner electrician.RelayClient
}

func (a relayAdapter) Request(ctx context.Context, rr core.RelayRequest) ([]byte, error) {
	return a.inner.Request(ctx, electrician.RelayRequest{
		Topic:   rr.Topic,
		Body:    rr.Body,
		Headers: rr.Headers,
	})
}

func (a relayAdapter) Publish(ctx context.Context, rr core.RelayRequest) error {
	return a.inner.Publish(ctx, electrician.RelayRequest{
		Topic:   rr.Topic,
		Body:    rr.Body,
		Headers: rr.Headers,
	})
}

func provideRelayForCore() (core.RelayClient, error) {
	ec, err := electrician.NewBuilderRelayFromEnv()
	if err != nil {
		return nil, err
	}
	if ec == nil {
		return nil, nil
	}
	return relayAdapter{inner: ec}, nil
}

// ---- Router ----

type routerDeps struct {
	fx.In

	Opts Options

	AuthMW *auth.Middleware
	LogMW  *logger.Middleware

	Metrics http.Handler `name:"metrics"`

	Typed core.TypedPublisher
	Rel   core.RelayClient
	R     httpx.Router
	Log   *zap.Logger
}

func provideRouter(d routerDeps) http.Handler {
	cfgPath := envOr(d.Opts.ManifestEnv, d.Opts.DefaultManifest)
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		d.Log.Fatal("manifest load failed", zap.Error(err), zap.String("path", cfgPath))
	}

	needsRelay := false
	for _, rt := range cfg.Routes {
		if rt.Handler.Type == manifest.HandlerType("relay.publish") {
			needsRelay = true
			break
		}
	}
	if needsRelay && d.Rel == nil {
		d.Log.Error("relay.publish configured but no RelayClient",
			zap.String("ELECTRICIAN_TARGET", os.Getenv("ELECTRICIAN_TARGET")),
			zap.String("OAUTH_ISSUER_BASE", os.Getenv("OAUTH_ISSUER_BASE")),
			zap.String("OAUTH_CLIENT_ID", os.Getenv("OAUTH_CLIENT_ID")),
		)
	}

	return core.BuildRouter(cfg, core.BuildDeps{
		Auth:    d.AuthMW,
		LogMW:   d.LogMW,
		Metrics: d.Metrics,
		Relay:   d.Rel,
		Typed:   d.Typed,
		Router:  d.R,
	})
}

// ---- Server lifecycle ----

type serverDeps struct {
	fx.In
	Opts   Options
	Logger *zap.Logger
	App    http.Handler `name:"app"`
}

func registerHooks(lc fx.Lifecycle, d serverDeps) {
	addr := envOr(d.Opts.ListenAddrEnv, d.Opts.DefaultListen)
	cert := os.Getenv(d.Opts.TLSCertEnv)
	key := os.Getenv(d.Opts.TLSKeyEnv)

	srv := &http.Server{
		Addr:         addr,
		Handler:      d.App,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}
	useTLS := fileExists(cert) && fileExists(key)

	cfgPath := envOr(d.Opts.ManifestEnv, d.Opts.DefaultManifest)
	cfg, err := core.LoadConfig(cfgPath)
	if err != nil {
		d.Logger.Fatal("manifest load failed", zap.Error(err), zap.String("path", cfgPath))
	}

	recvCtx, recvCancel := context.WithCancel(context.Background())

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// Boot receivers defined in manifest (non-blocking per receiver + pipeline).
			go func() {
				for _, rc := range cfg.Receivers {
					buf := rc.BufferSize
					if buf <= 0 {
						buf = 1024
					}
					for _, pl := range rc.Pipeline {
						datatype := pl.DataType
						names := append([]string(nil), pl.Transformers...)
						address := rc.Address
						buffer := buf

						go func(address string, buffer int, dt string, tnames []string) {
							stop, err := electrician.StartReceiverForwardFromEnvByName(
								recvCtx, address, buffer, dt, tnames,
							)
							if err != nil {
								d.Logger.Error("receiver start failed",
									zap.String("address", address),
									zap.String("datatype", dt),
									zap.Strings("transformers", tnames),
									zap.Error(err),
								)
								return
							}
							d.Logger.Info("receiver started",
								zap.String("address", address),
								zap.String("datatype", dt),
								zap.Strings("transformers", tnames),
							)
							go func() {
								<-recvCtx.Done()
								if stop != nil {
									stop()
								}
							}()
						}(address, buffer, datatype, names)
					}
				}
			}()

			// Start HTTP server.
			if useTLS {
				d.Logger.Info("server starting (TLS)",
					zap.String("service", d.Opts.Service),
					zap.String("addr", addr),
					zap.String("cert", cert),
				)
				go func() {
					if err := srv.ListenAndServeTLS(cert, key); err != nil && err != http.ErrServerClosed {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			} else {
				d.Logger.Info("server starting (PLAINTEXT)",
					zap.String("service", d.Opts.Service),
					zap.String("addr", addr),
				)
				go func() {
					srv.TLSConfig = nil
					if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			}
			return nil
		},
		OnStop: func(ctx context.Context) error {
			d.Logger.Info("server stopping", zap.String("service", d.Opts.Service))
			recvCancel()
			return srv.Shutdown(ctx)
		},
	})
}

// ---- Public Fx module ----

func Module(opts Options) fx.Option {
	return fx.Options(
		// Supply options to DI.
		fx.Supply(opts),

		// Middleware modules
		auth.Module,
		logger.Module,

		// Metrics (named)
		fx.Provide(fx.Annotate(metrics.ProvideMetrics, fx.ResultTags(`name:"metrics"`))),

		// Router implementation
		fx.Provide(httpx.NewChi),

		// Electrician publish path:
		// - typed publisher (adapts to core.TypedPublisher)
		fx.Provide(
			fx.Annotate(
				electrician.NewTypedPublisherFromEnv,
				fx.As(new(core.TypedPublisher)),
			),
		),
		// - byte relay client (wrap electrician client into core interface)
		fx.Provide(provideRelayForCore),

		// Router (named "app")
		fx.Provide(
			fx.Annotate(
				provideRouter,
				fx.ResultTags(`name:"app"`),
			),
		),

		// App lifecycle (starts receivers + HTTP server)
		fx.Invoke(registerHooks),
	)
}

// ---- helpers ----

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
