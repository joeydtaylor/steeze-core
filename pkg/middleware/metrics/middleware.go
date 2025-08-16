package metrics

import (
	"net/http"
	"strconv"
	"time"

	chimw "github.com/go-chi/chi/middleware"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
)

// Collect produces the HTTP middleware that records the counters/histogram.
func Collect(ca *auth.Middleware) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			startTime := time.Now()

			defer func() {
				// Skip self-scrape and any additional caller-configured paths
				if isSkipPath(r) {
					return
				}

				endTime := time.Since(startTime)

				role := ""
				if ca != nil {
					role = ca.GetUser(r.Context()).Role.Name
				}

				code := strconv.Itoa(ww.Status())
				uri := normalizePath(r) // path only; avoid cardinality explosion
				method := r.Method

				totalHttpRequestsFromRole.WithLabelValues(role).Inc()
				totalHttpRequestsToUri.WithLabelValues(code, uri, method).Inc()
				totalHttpRequests.WithLabelValues(code, method).Inc()
				responseTime.Observe(endTime.Seconds())
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
