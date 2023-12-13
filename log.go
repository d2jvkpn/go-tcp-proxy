package proxy

import (
	"fmt"
	"time"

	"github.com/mgutz/ansi"
)

// Logger - Interface to pass into Proxy for it to log messages
type Logger interface {
	Trace(f string, args ...any)
	Debug(f string, args ...any)
	Info(f string, args ...any)
	Warn(f string, args ...any)
	Error(f string, args ...any)
}

// NullLogger - An empty logger that ignores everything
type NullLogger struct{}

// Trace - no-op
func (l NullLogger) Trace(f string, args ...any) {}

// Debug - no-op
func (l NullLogger) Debug(f string, args ...any) {}

// Info - no-op
func (l NullLogger) Info(f string, args ...any) {}

// Warn - no-op
func (l NullLogger) Warn(f string, args ...any) {}

// Error - no-op
func (l NullLogger) Error(f string, args ...any) {}

// ColorLogger - A Logger that logs to stdout in color
type ColorLogger struct {
	VeryVerbose bool
	Verbose     bool
	Prefix      string
	Color       bool
}

// Trace - Log a very verbose trace message
func (l ColorLogger) Trace(f string, args ...any) {
	if !l.VeryVerbose {
		return
	}
	l.output("blue", f, args...)
}

// Debug - Log a debug message
func (l ColorLogger) Debug(f string, args ...any) {
	if !l.Verbose {
		return
	}
	l.output("white", f, args...)
}

// Info - Log a general message
func (l ColorLogger) Info(f string, args ...any) {
	l.output("green", f, args...)
}

// Warn - Log a warning
func (l ColorLogger) Warn(f string, args ...any) {
	l.output("yellow", f, args...)
}

// Warn - Log a warning
func (l ColorLogger) Error(f string, args ...any) {
	l.output("red", f, args...)
}

func (l ColorLogger) output(color, f string, args ...any) {
	if l.Color && color != "" {
		f = ansi.Color(f, color)
	}

	f = fmt.Sprintf("[%s] %s%s\n", time.Now().Format("2006-01-02T15:04:05.000Z07:00"), l.Prefix, f)
	fmt.Printf(f, args...)
}
