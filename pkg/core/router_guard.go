package core

import (
	"net/http"

	manifest "github.com/joeydtaylor/steeze-core/pkg/manifest"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
)

func withGuard(next http.HandlerFunc, a *auth.Middleware, g manifest.Guard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no auth middleware wired, only allow when route doesn't require auth
		if a == nil {
			if g.RequireAuth || len(g.Users) > 0 || len(g.Roles) > 0 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
			return
		}

		if g.RequireAuth && !a.IsAuthenticated(r.Context()) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if len(g.Users) > 0 {
			u := a.GetUser(r.Context()).Username
			if u == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			for _, x := range g.Users {
				if u == x {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if len(g.Roles) > 0 {
			u := a.GetUser(r.Context())
			if u.Username == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if a.IsAdmin(r.Context()) {
				next(w, r)
				return
			}
			for _, x := range g.Roles {
				if u.Role.Name == x {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
