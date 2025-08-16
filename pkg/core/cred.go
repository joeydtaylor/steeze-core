// core/cred.go
package core

import (
	"context"
	"net/http"

	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
)

type DownstreamCredentials struct {
	HeaderName  string
	HeaderValue string
	Extra       map[string]string
}

type CredentialsProvider interface {
	Issue(ctx context.Context, r *http.Request, route manifest.Route) (DownstreamCredentials, error)
}
