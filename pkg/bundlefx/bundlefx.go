// bundlefx/bundlefx.go
package bundlefx

import (
	"github.com/joeydtaylor/steeze-core/middleware/auth"
	"github.com/joeydtaylor/steeze-core/middleware/logger"
	"github.com/joeydtaylor/steeze-core/middleware/metrics"
	"go.uber.org/fx"
)

// Module provided to fx
var Module = fx.Options(
	auth.Module,
	logger.Module,
	metrics.Module,
)
