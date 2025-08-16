package core

import "net/http"

func writeJSON(w http.ResponseWriter, payload []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(payload) > 0 {
		_, _ = w.Write(payload)
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

func statusIf(s, def int) int {
	if s > 0 {
		return s
	}
	return def
}
