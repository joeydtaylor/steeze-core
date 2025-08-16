package metrics

import (
	"net/http"
	"strings"
	"sync"
)

var (
	skipMu    sync.RWMutex
	skipPaths = map[string]struct{}{"/metrics": {}}

	normMu         sync.RWMutex
	pathNormalizer = func(r *http.Request) string { return r.URL.Path }
)

// AddMetricsSkipPaths lets callers extend the skip list (default keeps only "/metrics").
func AddMetricsSkipPaths(paths ...string) {
	skipMu.Lock()
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			skipPaths[p] = struct{}{}
		}
	}
	skipMu.Unlock()
}

// SetPathNormalizer allows callers to normalize the URI label (e.g., collapse IDs).
// By default it returns r.URL.Path unchanged.
func SetPathNormalizer(fn func(*http.Request) string) {
	if fn == nil {
		return
	}
	normMu.Lock()
	pathNormalizer = fn
	normMu.Unlock()
}

func isSkipPath(r *http.Request) bool {
	p := r.URL.Path
	skipMu.RLock()
	_, ok := skipPaths[p]
	skipMu.RUnlock()
	return ok
}

func normalizePath(r *http.Request) string {
	normMu.RLock()
	fn := pathNormalizer
	normMu.RUnlock()
	return fn(r)
}
