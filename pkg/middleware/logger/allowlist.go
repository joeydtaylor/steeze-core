package logger

import (
	"net/http"
	"strings"
	"sync"
)

var (
	bodyLogMu    sync.RWMutex
	bodyLogPaths = map[string]struct{}{
		"/echo":     {},
		"/feedback": {},
	}
)

// AddBodyLogPaths lets callers extend the allowlist at runtime (optional).
func AddBodyLogPaths(paths ...string) {
	bodyLogMu.Lock()
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			bodyLogPaths[p] = struct{}{}
		}
	}
	bodyLogMu.Unlock()
}

// Only log small JSON request bodies on allowlisted routes.
func shouldLogBody(r *http.Request, body []byte) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return false
	}
	if len(body) == 0 || len(body) > 1<<16 { // 64 KiB cap
		return false
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return false
	}
	path := r.URL.Path
	bodyLogMu.RLock()
	_, ok := bodyLogPaths[path]
	bodyLogMu.RUnlock()
	return ok
}
