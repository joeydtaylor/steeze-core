package auth

import "net/http"

// HTTPDoer is satisfied by *http.Client and allows easy mocking in tests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
