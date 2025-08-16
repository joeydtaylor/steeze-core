package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewPromHttpHandler returns the /metrics handler.
func NewPromHttpHandler() http.Handler { return promhttp.Handler() }

// ProvideMetrics is the Fx provider used by your server wiring.
func ProvideMetrics() http.Handler { return NewPromHttpHandler() }
