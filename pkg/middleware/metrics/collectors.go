package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	responseTime = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "response_time",
			Help:    "http response time.",
			Buckets: []float64{0.5, 1, 5, 10, 30, 60},
		},
	)

	totalHttpRequestsFromRole = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests_from_role", Help: "http requests from role"},
		[]string{"role"},
	)

	totalHttpRequestsToUri = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests_to_uri", Help: "http requests to uri"},
		[]string{"code", "uri", "method"},
	)

	totalHttpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "total_http_requests", Help: "http requests by code, and method"},
		[]string{"code", "method"},
	)
)

func init() {
	prometheus.MustRegister(
		responseTime,
		totalHttpRequestsFromRole,
		totalHttpRequestsToUri,
		totalHttpRequests,
	)
}
