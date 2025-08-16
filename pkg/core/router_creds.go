package core

import (
	"net/http"
	"strings"

	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
)

func issueCreds(d BuildDeps, r *http.Request, rt manifest.Route) (DownstreamCredentials, error) {
	if d.Creds == nil {
		if rt.Policy.DownAuth == nil || rt.Policy.DownAuth.Type == "none" {
			return DownstreamCredentials{}, nil
		}
		switch rt.Policy.DownAuth.Type {
		case "passthrough-cookie":
			if sessionCookieName == "" {
				return DownstreamCredentials{}, nil
			}
			return PassthroughCookieProvider{CookieName: sessionCookieName}.Issue(r.Context(), r, rt)
		case "static-bearer":
			if staticBearerCached != "" {
				val := staticBearerCached
				if !strings.HasPrefix(val, "Bearer ") {
					val = "Bearer " + val
				}
				return DownstreamCredentials{HeaderName: "Authorization", HeaderValue: val}, nil
			}
			return StaticBearerProvider{}.Issue(r.Context(), r, rt)
		case "token-exchange":
			return TokenExchangeProvider{Auth: d.Auth}.Issue(r.Context(), r, rt)
		}
		return DownstreamCredentials{}, nil
	}
	return d.Creds.Issue(r.Context(), r, rt)
}
