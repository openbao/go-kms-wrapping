// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0

package securosyshsm

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
)

func newFileLogger(name, path, level string) (hclog.Logger, *os.File, error) {
	if path == "" {
		return nil, nil, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %q: %w", path, err)
	}

	return hclog.New(&hclog.LoggerOptions{
		Name:   name,
		Level:  parseLogLevel(level),
		Output: file,
	}), file, nil
}

func parseLogLevel(level string) hclog.Level {
	normalized := strings.ToLower(strings.TrimSpace(level))
	if normalized == "" {
		return hclog.Debug
	}
	switch normalized {
	case "trace":
		return hclog.Trace
	case "debug":
		return hclog.Debug
	case "warn", "warning":
		return hclog.Warn
	case "error":
		return hclog.Error
	case "off":
		return hclog.Off
	default:
		return hclog.Info
	}
}
