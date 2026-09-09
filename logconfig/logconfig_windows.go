//go:build windows

package logconfig

import (
	"os"
	"strings"

	phuslog "github.com/phuslu/log"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/hlandau/svcutils.v1/exepath"
)

func newStderrWriter() phuslog.Writer {
	return phuslog.IOWriter{Writer: os.Stderr}
}

func platformWriters(cfg *Config) []phuslog.Writer {
	if !cfg.Eventlog {
		return nil
	}

	source := cfg.EventlogName
	if source == "" {
		source = exepath.ProgramName
	}

	logger, err := eventlog.Open(source)
	if err != nil {
		return nil
	}

	return []phuslog.Writer{
		newSeverityWriter(&eventlogWriter{logger: logger}, cfg.EventlogSeverity, severityDebug),
	}
}

type eventlogWriter struct {
	logger *eventlog.Log
}

func (w *eventlogWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	message := strings.TrimSuffix(string(entry.Value()), "\n")

	var err error

	switch entry.Level {
	case phuslog.WarnLevel:
		err = w.logger.Warning(1, message)
	case phuslog.TraceLevel, phuslog.DebugLevel, phuslog.InfoLevel:
		err = w.logger.Info(1, message)
	case phuslog.ErrorLevel, phuslog.FatalLevel, phuslog.PanicLevel:
		err = w.logger.Error(1, message)
	default:
		err = w.logger.Info(1, message)
	}

	if err != nil {
		return 0, err
	}

	return len(entry.Value()), nil
}

func (w *eventlogWriter) Close() error {
	return w.logger.Close()
}
