// bundlefx/bundlefx.go
package bundlefx

import (
	"github.com/joeydtaylor/steeze-core/pkg/middleware/auth"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/logger"
	"github.com/joeydtaylor/steeze-core/pkg/middleware/metrics"
	"go.uber.org/fx"
)

// Module provided to fx
var Module = fx.Options(
	auth.Module,
	logger.Module,
	metrics.Module,
)
