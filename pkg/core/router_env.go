package core

import (
	"os"
	"strings"
)

// cache env once
var (
	sessionCookieName  = strings.TrimSpace(os.Getenv("SESSION_COOKIE_NAME"))
	staticBearerCached = strings.TrimSpace(os.Getenv("ELECTRICIAN_STATIC_BEARER"))
)
