package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func ensureLogDir() string {
	dir := "log"
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func NewLog(n string) *zap.Logger {
	_ = ensureLogDir()

	cfg := zap.NewProductionEncoderConfig()
	cfg.MessageKey = zapcore.OmitKey

	console := zapcore.Lock(os.Stdout)

	var logPath string
	if runtime.GOOS == "windows" {
		logPath = filepath.Join("log", n)
	} else {
		logPath = fmt.Sprintf("%s/%s", "log", n)
	}

	w := zapcore.AddSync(&lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    50, // MB
		MaxBackups: 3,
		MaxAge:     7, // days
	})

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), w, zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), console, zap.InfoLevel),
	)
	return zap.New(core)
}

// package-level singleton for access logs (unchanged behavior).
var httpAccessLogger = NewLog("http-access.log")

// SetAccessLogger lets tests/CLIs override the access logger (optional).
func SetAccessLogger(l *zap.Logger) {
	if l != nil {
		httpAccessLogger = l
	}
}
