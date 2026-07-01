package logconfig

import (
	"strings"

	phuslog "github.com/phuslu/log"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup       = cflag.NewGroup(nil, "xlog")
	logSeverityFlag = cflag.String(flagGroup, "severity", "NOTICE",
		"Log severity")
	loggers []*phuslog.CategorizedLogger
)

func New(category string) *phuslog.CategorizedLogger {
	logger := phuslog.DefaultLogger.Categorized(category)
	loggers = append(loggers, logger)
	return logger
}

func Init() {
	level, ok := parseSeverity(logSeverityFlag.Value())
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
