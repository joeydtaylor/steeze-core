package electrician

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// preflightOAuthToken attempts a quick client-credentials token call, backing off
// for up to 'total'. It's best-effort and errors are ignored by the caller.
func preflightOAuthToken(ctx context.Context, hc *http.Client, issuer, clientID, clientSecret string, scopes []string, total time.Duration) error {
	// Nothing to do if obviously misconfigured
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil
	}

	tokenURL := strings.TrimRight(issuer, "/") + "/api/auth/oauth/token"
	if _, err := url.Parse(tokenURL); err != nil {
		// don't block startup on a bad parse; forward relay will surface config errors
		return nil
	}

	// Backoff: 250ms -> 500ms -> 1s -> 2s ... until total budget is spent
	deadline := time.Now().Add(total)
	sleep := 250 * time.Millisecond

	for {
		// Respect ctx and budget
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
				// Success: token endpoint is responsive; good to start the forward relay
				return nil
			}
		}

		time.Sleep(sleep)
		if sleep < 2*time.Second {
			sleep *= 2
		}
	}
}
