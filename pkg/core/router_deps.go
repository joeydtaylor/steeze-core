package core

import (
	"net/http"

	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/logger"
	httpx "github.com/joeydtaylor/steeze-core/pkg/transport/httpx"
)

type BuildDeps struct {
	Auth    *auth.Middleware
	LogMW   *logger.Middleware
	Metrics http.Handler
	Relay   RelayClient
	Router  httpx.Router
	Typed   TypedPublisher
	Creds   CredentialsProvider
}
