//go:build !windows

package logconfig

import (
	"io"
	stdsyslog "log/syslog"
	"os"
	"strings"

	"github.com/coreos/go-systemd/v22/journal"
	phuslog "github.com/phuslu/log"
	"gopkg.in/hlandau/svcutils.v1/exepath"
	"gopkg.in/hlandau/svcutils.v1/systemd"
)

var syslogFacilities = map[string]stdsyslog.Priority{
	"kern":     stdsyslog.LOG_KERN,
	"user":     stdsyslog.LOG_USER,
	"mail":     stdsyslog.LOG_MAIL,
	"daemon":   stdsyslog.LOG_DAEMON,
	"auth":     stdsyslog.LOG_AUTH,
	"syslog":   stdsyslog.LOG_SYSLOG,
	"lpr":      stdsyslog.LOG_LPR,
	"news":     stdsyslog.LOG_NEWS,
	"uucp":     stdsyslog.LOG_UUCP,
	"cron":     stdsyslog.LOG_CRON,
	"authpriv": stdsyslog.LOG_AUTHPRIV,
	"ftp":      stdsyslog.LOG_FTP,
	"local0":   stdsyslog.LOG_LOCAL0,
	"local1":   stdsyslog.LOG_LOCAL1,
	"local2":   stdsyslog.LOG_LOCAL2,
	"local3":   stdsyslog.LOG_LOCAL3,
	"local4":   stdsyslog.LOG_LOCAL4,
	"local5":   stdsyslog.LOG_LOCAL5,
	"local6":   stdsyslog.LOG_LOCAL6,
	"local7":   stdsyslog.LOG_LOCAL7,
}

func platformWriters(cfg *Config) []phuslog.Writer {
	var writers []phuslog.Writer

	if cfg.Syslog {
		writer := newSyslogWriter(cfg.Facility)
		if writer != nil {
			writers = append(writers, newSeverityWriter(writer, cfg.SyslogSeverity, severityDebug))
		}
	}

	if cfg.Journal && journal.Enabled() {
		tags := map[string]string{"SYSLOG_FACILITY": cfg.Facility}
		if exepath.ProgramName != "" {
			tags["SYSLOG_TAG"] = exepath.ProgramName
		}

		writers = append(writers, newSeverityWriter(&journalWriter{tags: tags}, cfg.JournalSeverity, severityDebug))
	}

	return writers
}

func newStderrWriter() phuslog.Writer {
	if systemd.IsRunningUnder() {
		return &systemdStderrWriter{writer: os.Stderr}
	}

	return phuslog.IOWriter{Writer: os.Stderr}
}

type systemdStderrWriter struct {
	writer io.Writer
}

func (w *systemdStderrWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	var priority byte

	switch entry.Level {
	case phuslog.TraceLevel, phuslog.DebugLevel:
		priority = '7'
	case phuslog.InfoLevel:
		priority = '6'
	case phuslog.WarnLevel:
		priority = '4'
	case phuslog.ErrorLevel:
		priority = '3'
	case phuslog.FatalLevel, phuslog.PanicLevel:
		priority = '2'
	default:
		priority = '6'
	}

	message := append([]byte{'<', priority, '>'}, entry.Value()...)

	return w.writer.Write(message)
}

func newSyslogWriter(facilityName string) phuslog.Writer {
	facility, ok := syslogFacilities[strings.ToLower(strings.TrimSpace(facilityName))]
	if !ok {
		return nil
	}

	programName := exepath.ProgramName
	if programName == "" {
		programName = "unknown"
	}

	writer, err := stdsyslog.New(facility|stdsyslog.LOG_DEBUG, programName)
	if err != nil {
		return nil
	}

	return &syslogWriter{writer: writer}
}

type syslogWriter struct {
	writer *stdsyslog.Writer
}

func (w *syslogWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	message := strings.TrimSuffix(string(entry.Value()), "\n")

	var err error

	switch entry.Level {
	case phuslog.TraceLevel, phuslog.DebugLevel:
		err = w.writer.Debug(message)
	case phuslog.InfoLevel:
		err = w.writer.Info(message)
	case phuslog.WarnLevel:
		err = w.writer.Warning(message)
	case phuslog.ErrorLevel:
		err = w.writer.Err(message)
	case phuslog.FatalLevel, phuslog.PanicLevel:
		err = w.writer.Crit(message)
	default:
		err = w.writer.Info(message)
	}

	if err != nil {
		return 0, err
	}

	return len(entry.Value()), nil
}

func (w *syslogWriter) Close() error {
	return w.writer.Close()
}

type journalWriter struct {
	tags map[string]string
}

func (w *journalWriter) WriteEntry(entry *phuslog.Entry) (int, error) {
	var priority journal.Priority

	switch entry.Level {
	case phuslog.TraceLevel, phuslog.DebugLevel:
		priority = journal.PriDebug
	case phuslog.InfoLevel:
		priority = journal.PriInfo
	case phuslog.WarnLevel:
		priority = journal.PriWarning
	case phuslog.ErrorLevel:
		priority = journal.PriErr
	case phuslog.FatalLevel, phuslog.PanicLevel:
		priority = journal.PriCrit
	default:
		priority = journal.PriNotice
	}

	message := strings.TrimSuffix(string(entry.Value()), "\n")
	if err := journal.Send(message, priority, w.tags); err != nil {
		return 0, err
	}

	return len(entry.Value()), nil
}
