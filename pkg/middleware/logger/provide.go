package logger

import "go.uber.org/zap"

func ProvideLoggerMiddleware() *Middleware { return &Middleware{} }
func ProvideLogger() *zap.Logger           { return NewLog("system.log") }
