package auth

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProvideAuthentication wires defaults and env config.
// It non-fatally attempts to fetch the assertion key on startup.
func ProvideAuthentication() *Middleware {
	hc := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
		Timeout: 8 * time.Second,
	}

	leeway := 60 * time.Second
	if v := strings.TrimSpace(os.Getenv("ASSERTION_LEEWAY_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			leeway = time.Duration(n) * time.Second
		}
	}

	assertCookie := strings.TrimSpace(os.Getenv("ASSERTION_COOKIE_NAME"))
	if assertCookie == "" {
		assertCookie = "assert"
	}

	m := &Middleware{
		httpClient:       hc,
		sessionAPI:       os.Getenv("SESSION_STATE_API"),
		cookieName:       os.Getenv("SESSION_COOKIE_NAME"),
		adminRole:        os.Getenv("ADMIN_ROLE_NAME"),
		devBypass:        os.Getenv("AUTH_DEV_BYPASS") == "true",
		assertCookieName: assertCookie,
		assertKeyURL:     strings.TrimSpace(os.Getenv("ASSERTION_KEY_URL")), // JWKS/PEM endpoint
		assertKeyKID:     strings.TrimSpace(os.Getenv("ASSERTION_KEY_KID")),
		assertIssuer:     strings.TrimSpace(os.Getenv("ASSERTION_ISSUER")),
		assertAudience:   strings.TrimSpace(os.Getenv("ASSERTION_AUDIENCE")),
		assertLeeway:     leeway,
		cacheTTL:         1 * time.Hour, // default; overridable by Cache-Control
	}

	// Fetch assertion key on startup (non-fatal)
	if m.assertKeyURL != "" {
		if err := m.refreshAssertionKey(context.Background()); err == nil {
			go m.backgroundRefresh()
		}
	}

	return m
}
