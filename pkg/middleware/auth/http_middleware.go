package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (m *Middleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev bypass for local testing (NEVER enable in prod)
			if m.devBypass {
				if u := devUserFromHeaders(r); u.Username != "" {
					ctx := context.WithValue(r.Context(), userCtxKey, u)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 1) If assertion cookie present, validate locally
			if ac, _ := r.Cookie(m.assertCookieName); ac != nil && ac.Value != "" && m.getKey() != nil {
				if u, err := m.validateAssertion(ac.Value); err == nil && u.Username != "" {
					ctx := context.WithValue(r.Context(), userCtxKey, u)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// fall through on error; do not 401 yet
			}

			// 2) Fallback to session API if session cookie present
			if m.cookieName != "" {
				if c, err := r.Cookie(m.cookieName); err == nil && c != nil && c.Value != "" {
					if u, err := m.validateSession(r.Context(), c); err == nil && u.Username != "" {
						ctx := context.WithValue(r.Context(), userCtxKey, u)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			// 3) No cookies; continue unauthenticated
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) validateSession(ctx context.Context, c *http.Cookie) (User, error) {
	if m.sessionAPI == "" {
		return User{}, errors.New("SESSION_STATE_API not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.sessionAPI, nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.AddCookie(c)

	res, err := m.httpClient.Do(req)
	if err != nil {
		return User{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("session api status %d", res.StatusCode)
	}

	var u User
	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		return User{}, err
	}
	return u, nil
}
