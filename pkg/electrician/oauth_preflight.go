// pkg/electrician/oauth_preflight.go
package electrician

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func preflightOAuthToken(ctx context.Context, hc *http.Client, issuer, clientID, clientSecret string, scopes []string, total time.Duration) error {
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	tokenURL := strings.TrimRight(issuer, "/") + "/api/auth/oauth/token"
	if _, err := url.Parse(tokenURL); err != nil {
		return nil
	}

	deadline := time.Now().Add(total)
	sleep := 250 * time.Millisecond

	for {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ctx.Err()
		}
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		if len(scopes) > 0 {
			form.Set("scope", strings.Join(scopes, " "))
		}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := hc.Do(req)
		cancel()

		if err == nil && resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		time.Sleep(sleep)
		if sleep < 2*time.Second {
			sleep *= 2
		}
	}
}
