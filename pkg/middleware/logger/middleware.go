package logger

import (
	"bytes"
	"io"
	"net/http"
	"time"

	chimd "github.com/go-chi/chi/v5/middleware"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
	"github.com/joeydtaylor/steeze-core/pkg/utils"
	"go.uber.org/zap"
)

func (m *Middleware) Middleware(ca *auth.Middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := httpAccessLogger

			// Wrap writer
			ww := utils.NewWrapResponseWriter(w, r.ProtoMajor)

			// Read and RESTORE request body so downstream can consume it
			var body []byte
			if r.Body != nil {
				if b, err := io.ReadAll(r.Body); err == nil {
					body = b
				}
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}

			start := time.Now()
			defer func() {
				lat := time.Since(start)

				// nil-safe auth lookups
				isAuth := false
				username := ""
				role := ""
				provider := ""
				if ca != nil {
					isAuth = ca.IsAuthenticated(r.Context())
					u := ca.GetUser(r.Context())
					username = u.Username
					role = u.Role.Name
					provider = u.AuthenticationSource.Provider
				}

				pathOnly := r.URL.Path
				log := l.With(
					zap.String("dateTime", start.UTC().Format(time.RFC1123)),
					zap.String("requestId", chimd.GetReqID(r.Context())),
					zap.String("httpScheme", scheme),
					zap.Bool("isAuthenticated", isAuth),
					zap.String("username", username),
					zap.String("role", role),
					zap.String("authenticationProvider", provider),
					zap.String("httpProto", r.Proto),
					zap.String("httpMethod", r.Method),
					zap.String("remoteAddr", r.RemoteAddr),
					zap.String("uri", pathOnly),
					zap.Duration("lat", lat),
					zap.Int("responseSize", ww.BytesWritten()),
					zap.Int("status", ww.Status()),
				)

				// Redact by default; allowlist small JSON bodies only.
				if shouldLogBody(r, body) {
					log.Info("", zap.ByteString("requestData", body))
				} else {
					log.Info("")
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
