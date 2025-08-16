package core

import (
	"net/http"
	"strings"
	"time"

	chimd "github.com/go-chi/chi/v5/middleware"
	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
	hmetrics "github.com/joeydtaylor/steeze-core/pkg/middleware/metrics"
)

func BuildRouter(cfg manifest.Config, d BuildDeps) http.Handler {
	r := d.Router
	r.Use(chimd.RequestID, chimd.Recoverer, chimd.Heartbeat("/ping"))

	if d.Auth != nil {
		r.Use(d.Auth.Middleware())
		if d.LogMW != nil {
			r.Use(d.LogMW.Middleware(d.Auth))
		}
		// metrics collector that references auth state without copying it
		r.Use(hmetrics.Collect(d.Auth))
	} else if d.LogMW != nil {
		r.Use(d.LogMW.Middleware(nil))
	}

	r.Handle(http.MethodGet, "/metrics", d.Metrics)

	for _, rt := range cfg.Routes {
		h := wrapRoute(rt, d)
		if rt.Policy.TimeoutMS > 0 {
			t := time.Duration(rt.Policy.TimeoutMS) * time.Millisecond
			h = withTimeout(h, t)
		}
		h = withGuard(h, d.Auth, rt.Guard)

		switch strings.ToUpper(rt.Method) {
		case http.MethodGet:
			r.Get(rt.Path, h)
		case http.MethodPost:
			r.Post(rt.Path, h)
		case http.MethodPut:
			r.Put(rt.Path, h)
		case http.MethodDelete:
			r.Delete(rt.Path, h)
		default:
			r.Handle(rt.Method, rt.Path, h)
		}
	}
	return r.Mux()
}
