package logconfig

import (
	"strings"

	phuslog "github.com/phuslu/log"
)

type Config struct {
	Severity string `default:"NOTICE" usage:"Log severity"`
}

var loggers []*phuslog.CategorizedLogger

func New(category string) *phuslog.CategorizedLogger {
	logger := phuslog.DefaultLogger.Categorized(category)
	loggers = append(loggers, logger)
	return logger
}

func Init(cfg *Config) {
	level, ok := parseSeverity(cfg.Severity)
	if !ok {
		return
	}

	phuslog.DefaultLogger.SetLevel(level)
	for _, logger := range loggers {
		logger.SetLevel(level)
	}
}

func parseSeverity(severity string) (phuslog.Level, bool) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "TRACE":
		return phuslog.TraceLevel, true
	case "DEBUG":
		return phuslog.DebugLevel, true
	case "INFO":
		return phuslog.InfoLevel, true
	case "NOTICE", "WARN":
		return phuslog.WarnLevel, true
	case "ERROR":
		return phuslog.ErrorLevel, true
	case "CRITICAL", "ALERT", "EMERGENCY":
		return phuslog.FatalLevel, true
	default:
		return 0, false
	}
}
