package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/buhuipao/anyproxy/pkg/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

var defaultLogger *slog.Logger

// Init initializes the global logger based on configuration
func Init(cfg *config.LogConfig) error {
	// Set default values if not provided
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	if cfg.Format == "" {
		cfg.Format = "text"
	}
	if cfg.Output == "" {
		cfg.Output = "stdout"
	}

	// Parse log level
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %v", cfg.Level, err)
	}

	// Create output writer
	var writer io.Writer
	switch strings.ToLower(cfg.Output) {
	case "stdout":
		writer = os.Stdout
	case "stderr":
		writer = os.Stderr
	case "file":
		if cfg.File == "" {
			return fmt.Errorf("log file path is required when output is 'file'")
		}

		// Create directory if it doesn't exist
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory %s: %v", dir, err)
		}

		// Set default rotation values if not provided
		maxSize := cfg.MaxSize
		if maxSize == 0 {
			maxSize = 100 // 100MB default
		}
		maxBackups := cfg.MaxBackups
		if maxBackups == 0 {
			maxBackups = 3 // Keep 3 old files by default
		}
		maxAge := cfg.MaxAge
		if maxAge == 0 {
			maxAge = 28 // Keep files for 28 days by default
		}

		// Use lumberjack for log rotation
		writer = &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     maxAge,
			Compress:   cfg.Compress,
		}
	default:
		// Treat as file path
		if err := os.MkdirAll(filepath.Dir(cfg.Output), 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %v", err)
		}

		file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %v", cfg.Output, err)
		}
		writer = file
	}

	// Create handler based on format
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)
	case "text":
		handler = slog.NewTextHandler(writer, opts)
	default:
		return fmt.Errorf("unsupported log format: %s", cfg.Format)
	}

	// Create and set the default logger
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)

	return nil
}

// parseLevel converts string level to slog.Level
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown level: %s", level)
	}
}

// GetLogger returns the default logger
func GetLogger() *slog.Logger {
	if defaultLogger == nil {
		// Return a default logger if not initialized
		return slog.Default()
	}
	return defaultLogger
}

// Debug logs a debug message
func Debug(msg string, args ...any) {
	GetLogger().Debug(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...any) {
	GetLogger().Info(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	GetLogger().Warn(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...any) {
	GetLogger().Error(msg, args...)
}

// With returns a logger with the given attributes
func With(args ...any) *slog.Logger {
	return GetLogger().With(args...)
}
