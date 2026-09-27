package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

const DefaultLogLevel = "warn"

// ParseLogLevel converts a configured log level into its slog representation.
func ParseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", level)
	}
}

// NewLogger creates a text logger at the configured level. Logs are directed
// to stderr by default so they do not interfere with machine-readable output.
func NewLogger(level string, output io.Writer) *slog.Logger {
	slogLevel, err := ParseLogLevel(level)
	if err != nil {
		slogLevel, _ = ParseLogLevel(DefaultLogLevel)
	}
	if output == nil {
		output = os.Stderr
	}
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: slogLevel}))
}
