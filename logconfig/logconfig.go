package logconfig

import (
	"os"
	"strings"

	phuslog "github.com/phuslu/log"
)

type Config struct {
	Severity         string `default:"NOTICE" usage:"Log severity (any syslog severity name or number (0-7) or 'trace' (8) (most verbose))"`
	File             string `default:"" usage:"Log to filename"`
	FileSeverity     string `default:"TRACE" usage:"File logging severity limit"`
	Stderr           bool   `default:"true" usage:"Log to stderr?"`
	StderrSeverity   string `default:"TRACE" usage:"stderr logging severity limit"`
	Facility         string `default:"daemon" usage:"Syslog facility to use"`
	Syslog           bool   `default:"false" usage:"Log to syslog?"`
	SyslogSeverity   string `default:"DEBUG" usage:"Syslog severity limit"`
	Journal          bool   `default:"false" usage:"Log to systemd journal?"`
	JournalSeverity  string `default:"DEBUG" usage:"Systemd journal severity limit"`
	Eventlog         bool   `default:"false" usage:"Log to event log?"`
	EventlogName     string `default:"" usage:"Event log source name (uses .exe program name if unset)"`
	EventlogSeverity string `default:"DEBUG" usage:"Event log severity limit"`
}

var loggers []*phuslog.CategorizedLogger

const (
	severityEmergency = iota
	severityAlert
	severityCritical
	severityError
	severityWarn
	severityNotice
	severityInfo
	severityDebug
	severityTrace
)

var severityValues = map[string]int{
	"EMERGENCY": severityEmergency,
	"ALERT":     severityAlert,
	"CRITICAL":  severityCritical,
	"ERROR":     severityError,
	"WARN":      severityWarn,
	"NOTICE":    severityNotice,
	"INFO":      severityInfo,
	"DEBUG":     severityDebug,
	"TRACE":     severityTrace,
	"0":         severityEmergency,
	"1":         severityAlert,
	"2":         severityCritical,
	"3":         severityError,
	"4":         severityWarn,
	"5":         severityNotice,
	"6":         severityInfo,
	"7":         severityDebug,
	"8":         severityTrace,
}

type severityWriter struct {
	minSeverity int
	writer      phuslog.Writer
}

type exitStatusWriter struct {
	writer phuslog.Writer
}

func (w *exitStatusWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	n, err := w.writer.WriteEntry(entry)
	if entry.Level == phuslog.FatalLevel {
		os.Exit(1)
	}

	return n, err
}

func (w *severityWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	if entrySeverity(entry.Level) > w.minSeverity {
		return 0, nil
	}

	return w.writer.WriteEntry(entry)
}

func New(category string) *phuslog.CategorizedLogger {
	logger := phuslog.DefaultLogger.Categorized(category)
	loggers = append(loggers, logger)

	return logger
}

func Init(cfg *Config) {
	severity, ok := parseSeverityValue(cfg.Severity)
	if !ok {
		severity = severityTrace
	}

	level := phuslogLevel(severity)
	phuslog.DefaultLogger.SetLevel(level)

	var writers []phuslog.Writer
	if cfg.Stderr {
		writers = append(writers, newSeverityWriter(newStderrWriter(), cfg.StderrSeverity, severityTrace))
	}

	writers = append(writers, platformWriters(cfg)...)

	if cfg.File != "" {
		//nolint:gosec // The log file path is configured by the user.
		file, err := os.Create(cfg.File)
		if err == nil {
			writers = append(writers, newSeverityWriter(phuslog.IOWriteCloser{WriteCloser: file}, cfg.FileSeverity, severityTrace))
		}
	}

	multiWriter := phuslog.MultiEntryWriter(writers)
	writer := &exitStatusWriter{writer: &multiWriter}
	phuslog.DefaultLogger.Writer = writer

	for _, logger := range loggers {
		logger.SetLevel(level)
		logger.Writer = writer
	}
}

func newSeverityWriter(writer phuslog.Writer, severity string, fallback int) phuslog.Writer {
	minSeverity, ok := parseSeverityValue(severity)
	if !ok {
		minSeverity = fallback
	}

	return &severityWriter{minSeverity: minSeverity, writer: writer}
}

func parseSeverityValue(severity string) (int, bool) {
	value, ok := severityValues[strings.ToUpper(strings.TrimSpace(severity))]

	return value, ok
}

func phuslogLevel(severity int) phuslog.Level {
	switch {
	case severity >= severityTrace:
		return phuslog.TraceLevel
	case severity >= severityDebug:
		return phuslog.DebugLevel
	case severity >= severityInfo:
		return phuslog.InfoLevel
	case severity >= severityWarn:
		return phuslog.WarnLevel
	case severity >= severityError:
		return phuslog.ErrorLevel
	default:
		return phuslog.FatalLevel
	}
}

func entrySeverity(level phuslog.Level) int {
	switch level {
	case phuslog.TraceLevel:
		return severityTrace
	case phuslog.DebugLevel:
		return severityDebug
	case phuslog.InfoLevel:
		return severityInfo
	case phuslog.WarnLevel:
		return severityWarn
	case phuslog.ErrorLevel:
		return severityError
	case phuslog.FatalLevel, phuslog.PanicLevel:
		return severityCritical
	default:
		return severityTrace
	}
}
