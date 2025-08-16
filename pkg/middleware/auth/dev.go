package auth

import "net/http"

// Dev-only user injection via headers when AUTH_DEV_BYPASS=true
func devUserFromHeaders(r *http.Request) User {
	user := r.Header.Get("X-Dev-User")
	if user == "" {
		return User{}
	}
	role := r.Header.Get("X-Dev-Role")
	prov := r.Header.Get("X-Dev-Provider")
	return User{
		Username:             user,
		AuthenticationSource: AuthenticationSource{Provider: prov},
		Role:                 Role{Name: role},
	}
}
