package auth

import (
	"crypto/rsa"
	"sync"
	"time"
)

type Middleware struct {
	httpClient HTTPDoer
	sessionAPI string
	cookieName string
	adminRole  string
	devBypass  bool

	// Assertion verification
	assertCookieName string
	assertKeyURL     string
	assertKeyKID     string
	assertIssuer     string
	assertAudience   string
	assertLeeway     time.Duration

	// guarded by mu
	mu         sync.RWMutex
	assertKey  *rsa.PublicKey
	assertETag string
	cacheTTL   time.Duration
	lastFetch  time.Time
}
