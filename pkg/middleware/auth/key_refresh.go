package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (m *Middleware) backgroundRefresh() {
	for {
		sleep := m.getCacheTTL()
		if sleep < 5*time.Second {
			sleep = 5 * time.Second
		}
		time.Sleep(sleep)
		_ = m.refreshAssertionKey(context.Background())
	}
}

func (m *Middleware) refreshAssertionKey(ctx context.Context) error {
	if m.assertKeyURL == "" {
		return errors.New("ASSERTION_KEY_URL not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.assertKeyURL, nil)
	if err != nil {
		return err
	}
	if etag := m.getETag(); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("Accept", "*/*")

	res, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Honor 304 with previous key
	if res.StatusCode == http.StatusNotModified && m.getKey() != nil {
		m.updateCacheTTLFromHeaders(res)
		m.setLastFetch(time.Now())
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("key fetch %s: %s", m.assertKeyURL, res.Status)
	}

	ct := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Type")))
	var pub *rsa.PublicKey

	if strings.Contains(ct, "application/json") || strings.HasSuffix(strings.ToLower(m.assertKeyURL), ".json") {
		// JWKS
		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Use string `json:"use"`
				Alg string `json:"alg"`
				Kid string `json:"kid"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
			return err
		}

		var sel *struct {
			Kty, Use, Alg, Kid, N, E string
		}

		for i := range jwks.Keys {
			k := &jwks.Keys[i]
			if k.Kty != "RSA" {
				continue
			}
			if m.assertKeyKID != "" {
				if k.Kid == m.assertKeyKID {
					sel = &struct {
						Kty, Use, Alg, Kid, N, E string
					}{k.Kty, k.Use, k.Alg, k.Kid, k.N, k.E}
					break
				}
				continue
			}
			// default: first RSA signing key (RS256)
			if (k.Use == "" || k.Use == "sig") && (k.Alg == "" || strings.EqualFold(k.Alg, "RS256")) {
				sel = &struct {
					Kty, Use, Alg, Kid, N, E string
				}{k.Kty, k.Use, k.Alg, k.Kid, k.N, k.E}
				break
			}
		}
		if sel == nil {
			return errors.New("no suitable RSA key in JWKS")
		}
		nBytes, err := b64url(sel.N)
		if err != nil {
			return fmt.Errorf("bad jwks.n: %w", err)
		}
		eBytes, err := b64url(sel.E)
		if err != nil {
			return fmt.Errorf("bad jwks.e: %w", err)
		}
		pub = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: bytesToInt(eBytes),
		}
	} else {
		// PEM
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return errors.New("no PEM block in response")
		}
		keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		rk, ok := keyAny.(*rsa.PublicKey)
		if !ok {
			return errors.New("PEM is not RSA public key")
		}
		pub = rk
	}

	// commit new state under lock
	m.mu.Lock()
	m.assertKey = pub
	m.assertETag = res.Header.Get("ETag")
	m.updateCacheTTLFromHeadersLocked(res) // expects m.mu held
	m.lastFetch = time.Now()
	m.mu.Unlock()
	return nil
}

func (m *Middleware) updateCacheTTLFromHeaders(res *http.Response) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCacheTTLFromHeadersLocked(res)
}

func (m *Middleware) updateCacheTTLFromHeadersLocked(res *http.Response) {
	cc := res.Header.Get("Cache-Control")
	if cc == "" {
		return
	}
	parts := strings.Split(cc, ",")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if strings.HasPrefix(p, "max-age=") {
			if s, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil && s >= 5 {
				m.cacheTTL = time.Duration(s) * time.Second
				return
			}
		}
	}
}

func (m *Middleware) getKey() *rsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assertKey
}

func (m *Middleware) getETag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assertETag
}

func (m *Middleware) getCacheTTL() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cacheTTL
}

func (m *Middleware) setLastFetch(t time.Time) {
	m.mu.Lock()
	m.lastFetch = t
	m.mu.Unlock()
}
