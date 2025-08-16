package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (m *Middleware) validateAssertion(raw string) (User, error) {
	pub := m.getKey()
	if pub == nil {
		return User{}, errors.New("assertion key not configured")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(m.assertLeeway),
	)

	var claims struct {
		jwt.RegisteredClaims
		Ver   int      `json:"ver"`
		SID   string   `json:"sid"`
		UID   string   `json:"uid"`
		Org   string   `json:"org"`
		Roles []string `json:"roles"`
		Role  string   `json:"role"`
	}

	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil || !tok.Valid {
		return User{}, errors.New("invalid assertion")
	}

	if m.assertIssuer != "" && claims.Issuer != m.assertIssuer {
		return User{}, errors.New("bad issuer")
	}

	if m.assertAudience != "" {
		found := false
		for _, a := range claims.Audience {
			if a == m.assertAudience {
				found = true
				break
			}
		}
		if !found {
			return User{}, errors.New("bad audience")
		}
	}

	username := claims.UID
	if username == "" {
		username = claims.Subject
	}
	if username == "" {
		return User{}, errors.New("missing uid")
	}

	return User{
		Username:             username,
		AuthenticationSource: AuthenticationSource{Provider: "assert"},
		Role:                 Role{Name: firstNonEmpty(claims.Role, first(claims.Roles...))},
	}, nil
}

// silence unused import warning when not used elsewhere
var _ = time.Second
