package serverfx

import (
	"context"
	"crypto/tls"
	"errors"
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

// ---------- Options ----------

type Config struct {
	Service         string // for logs/metrics tags only
	ManifestEnv     string // e.g., HERMES_MANIFEST / EXODUS_MANIFEST
	DefaultManifest string // e.g., "manifest.toml"
	ListenEnv       string // SERVER_LISTEN_ADDRESS
	TLSCertEnv      string // SSL_SERVER_CERTIFICATE
	TLSKeyEnv       string // SSL_SERVER_KEY
}

type Option func(*Config)

func WithService(s string) Option            { return func(c *Config) { c.Service = s } }
func WithManifestEnv(k string) Option        { return func(c *Config) { c.ManifestEnv = k } }
func WithDefaultManifest(path string) Option { return func(c *Config) { c.DefaultManifest = path } }
func WithListenEnv(k string) Option          { return func(c *Config) { c.ListenEnv = k } }
func WithTLSCertKeyEnv(cert, key string) Option {
	return func(c *Config) { c.TLSCertEnv, c.TLSKeyEnv = cert, key }
}

func defaultConfig() Config {
	return Config{
		Service:         "app",
		ManifestEnv:     "APP_MANIFEST",
		DefaultManifest: "manifest.toml",
		ListenEnv:       "SERVER_LISTEN_ADDRESS",
		TLSCertEnv:      "SSL_SERVER_CERTIFICATE",
		TLSKeyEnv:       "SSL_SERVER_KEY",
	}
}

// Module returns a complete Fx option set; add app-specific fx.Invoke(...) alongside.
func Module(opts ...Option) fx.Option {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	return fx.Options(
		// Core middleware
		auth.Module,
		logger.Module,
		fx.Provide(fx.Annotate(metrics.ProvideMetrics, fx.ResultTags(`name:"metrics"`))),
		// Router impl
		fx.Provide(httpx.NewChi),
		// Config into DI
		fx.Provide(func() Config { return cfg }),
		// Electrician publish path
		fx.Provide(fx.Annotate(electrician.NewTypedPublisherFromEnv, fx.As(new(core.TypedPublisher)))),
		fx.Provide(provideRelayClient),
		// Router
		fx.Provide(fx.Annotate(
			provideRouter,
			fx.ParamTags(``, ``, `name:"metrics"`, ``, ``, ``, ``), // a,lm,m,typed,rel,r,zl
			fx.ResultTags(`name:"app"`),
		)),
		// Lifecycle
		fx.Invoke(registerHooks),
	)
}

// ---------- Relay adapter ----------

type relayAdapter struct{ inner electrician.RelayClient }

func (a relayAdapter) Request(ctx context.Context, rr core.RelayRequest) ([]byte, error) {
	return a.inner.Request(ctx, electrician.RelayRequest{Topic: rr.Topic, Body: rr.Body, Headers: rr.Headers})
}
func (a relayAdapter) Publish(ctx context.Context, rr core.RelayRequest) error {
	return a.inner.Publish(ctx, electrician.RelayRequest{Topic: rr.Topic, Body: rr.Body, Headers: rr.Headers})
}

func provideRelayClient() (core.RelayClient, error) {
	ec, err := electrician.NewBuilderRelayFromEnv()
	if err != nil {
		return nil, err
	}
	if ec == nil {
		return nil, nil // noop when no ELECTRICIAN_TARGET
	}
	return relayAdapter{inner: ec}, nil
}

// ---------- Router ----------

func provideRouter(
	cfg Config,
	a *auth.Middleware,
	lm *logger.Middleware,
	/* name:"metrics" */ m http.Handler,
	typed core.TypedPublisher,
	rel core.RelayClient,
	r httpx.Router,
	zl *zap.Logger,
) http.Handler {
	cfgPath := envOr(cfg.ManifestEnv, cfg.DefaultManifest)
	man, err := core.LoadConfig(cfgPath)
	if err != nil {
		zl.Fatal("manifest load failed", zap.Error(err), zap.String("path", cfgPath))
	}

	// Fail-safety: warn if manifest needs relay but none provided.
	needsRelay := false
	for _, rt := range man.Routes {
		if rt.Handler.Type == manifest.HandlerType("relay.publish") {
			needsRelay = true
			break
		}
	}
	if needsRelay && rel == nil {
		zl.Error("relay.publish configured but no RelayClient",
			zap.String("ELECTRICIAN_TARGET", os.Getenv("ELECTRICIAN_TARGET")),
			zap.String("OAUTH_ISSUER_BASE", os.Getenv("OAUTH_ISSUER_BASE")),
			zap.String("OAUTH_CLIENT_ID", os.Getenv("OAUTH_CLIENT_ID")),
		)
	}

	return core.BuildRouter(man, core.BuildDeps{
		Auth:    a,
		LogMW:   lm,
		Metrics: m,
		Relay:   rel,
		Typed:   typed,
		Router:  r,
	})
}

// ---------- Lifecycle (receivers + HTTP server) ----------

type serverDeps struct {
	fx.In
	Logger *zap.Logger
	App    http.Handler `name:"app"`
}

func registerHooks(lc fx.Lifecycle, cfg Config, d serverDeps) {
	addr := envOr(cfg.ListenEnv, ":4000")
	cert := os.Getenv(cfg.TLSCertEnv)
	key := os.Getenv(cfg.TLSKeyEnv)

	srv := &http.Server{
		Addr:         addr,
		Handler:      d.App,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	}
	useTLS := fileExists(cert) && fileExists(key)

	// Load manifest once to boot receivers.
	cfgPath := envOr(cfg.ManifestEnv, cfg.DefaultManifest)
	man, err := core.LoadConfig(cfgPath)
	if err != nil {
		d.Logger.Fatal("manifest load failed", zap.Error(err), zap.String("path", cfgPath))
	}

	recvCtx, recvCancel := context.WithCancel(context.Background())

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// Boot receivers (non-blocking fan-out).
			go func() {
				for _, rc := range man.Receivers {
					buf := rc.BufferSize
					if buf <= 0 {
						buf = 1024
					}
					for _, pl := range rc.Pipeline {
						dt := pl.DataType
						names := append([]string(nil), pl.Transformers...)
						addr := rc.Address

						go func() {
							stop, err := electrician.StartReceiverForwardFromEnvByName(recvCtx, addr, buf, dt, names)
							if err != nil {
								d.Logger.Error("receiver start failed",
									zap.String("address", addr),
									zap.String("datatype", dt),
									zap.Strings("transformers", names),
									zap.Error(err),
								)
								return
							}
							d.Logger.Info("receiver started",
								zap.String("address", addr),
								zap.String("datatype", dt),
								zap.Strings("transformers", names),
							)
							go func() {
								<-recvCtx.Done()
								if stop != nil {
									stop()
								}
							}()
						}()
					}
				}
			}()

			// Start HTTP.
			if useTLS {
				d.Logger.Info("server starting (TLS)", zap.String("addr", addr), zap.String("cert", cert))
				go func() {
					if err := srv.ListenAndServeTLS(cert, key); err != nil && !errors.Is(err, http.ErrServerClosed) {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			} else {
				d.Logger.Info("server starting (PLAINTEXT)", zap.String("addr", addr))
				go func() {
					srv.TLSConfig = nil
					if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						d.Logger.Fatal("server failed", zap.Error(err))
					}
				}()
			}
			return nil
		},
		OnStop: func(ctx context.Context) error {
			d.Logger.Info("server stopping")
			recvCancel()
			return srv.Shutdown(ctx)
		},
	})
}

// ---------- tiny helpers ----------

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
