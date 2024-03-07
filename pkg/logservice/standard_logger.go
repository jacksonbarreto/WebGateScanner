package logservice

import (
	"fmt"
	"log"
	"os"
)

type StandardLogger struct {
	idService string
	level     LogLevel
	logger    *log.Logger
}

func NewLogService(idService string) *StandardLogger {
	return &StandardLogger{
		idService: idService,
		level:     LogLevelInfo,
		logger:    log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *StandardLogger) Info(format string, v ...interface{}) {
	if l.level <= LogLevelInfo {
		l.log("[INFO] ", format, v...)
	}
}

func (l *StandardLogger) Warn(format string, v ...interface{}) {
	if l.level <= LogLevelWarn {
		l.log("[WARN]", format, v...)
	}
}

func (l *StandardLogger) Error(format string, v ...interface{}) {
	if l.level <= LogLevelError {
		l.log("[ERROR]", format, v...)
	}
}

func (l *StandardLogger) Debug(format string, v ...interface{}) {
	if l.level <= LogLevelDebug {
		l.log("[DEBUG]", format, v...)
	}
}

func (l *StandardLogger) SetLevel(level LogLevel) {
	l.level = level
}

func (l *StandardLogger) log(levelPrefix, format string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(format, v...)
	l.logger.Printf("%s %s -- %s", levelPrefix, l.idService, formattedMessage)
}
