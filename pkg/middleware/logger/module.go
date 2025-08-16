package logger

import "go.uber.org/fx"

var Module = fx.Options(
	fx.Provide(ProvideLoggerMiddleware),
	fx.Provide(ProvideLogger),
)
