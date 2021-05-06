package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Escape is the ANSI escape sequence.
const Escape = "\x1b"

// Attribute represents a style.
type Attribute int

// Base attributes
// nolint:deadcode
const (
	Reset Attribute = iota
	Bold
	Faint
	Italic
	Underline
	BlinkSlow
	BlinkRapid
	ReverseVideo
	Concealed
	CrossedOut
)

// Foreground text colors
// nolint:deadcode
const (
	FgBlack Attribute = iota + 30
	FgRed
	FgGreen
	FgYellow
	FgBlue
	FgMagenta
	FgCyan
	FgWhite
)

type baseLogger struct {
	Verbose         bool
	PrintTimestamps bool
	NoColor         bool
	HostInfoCache   *HostInfoCache
	NoHostInfo      bool

	wg sync.WaitGroup
}

func newBaseLogger() *baseLogger {
	return &baseLogger{
		PrintTimestamps: true,
		HostInfoCache:   NewHostInfoCache(),
	}
}

// Logger provides logging functionality.
type Logger struct {
	*baseLogger
	Prefix string
}

// NewLogger returns a Logger.
func NewLogger() *Logger {
	return &Logger{
		baseLogger: newBaseLogger(),
	}
}

func (l *Logger) style(attrs ...Attribute) string {
	if l.NoColor {
		return ""
	}

	s := ""
	for _, a := range attrs {
		s += fmt.Sprintf("%s[%dm", Escape, a)
	}

	return s
}

// WithPrefix returns a copy of the logger with a new prefix.
func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{
		baseLogger: l.baseLogger,
		Prefix:     prefix,
	}
}

// Debugf prints debug information.
func (l *Logger) Debugf(format string, a ...interface{}) {
	if !l.Verbose {
		return
	}

	l.logf(os.Stdout, l.styleAndPrefix(Faint)+format, a...)
}

// Infof prints info messages.
func (l *Logger) Infof(format string, a ...interface{}) {
	l.logf(os.Stdout, l.styleAndPrefix()+format, a...)
}

// Query prints query information.
func (l *Logger) Query(name string, dnsType string, peer net.IP) {
	typeAnnotation := ""
	if dnsType != "" {
		typeAnnotation = " (" + dnsType + ")"
	}

	l.logWithHostInfo(peer, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix(FgGreen)+"%q%s queried by %s", name, typeAnnotation, hostInfo)
	})
}

// IgnoreDNS prints information abound ignored DNS queries.
func (l *Logger) IgnoreDNS(name string, dnsType string, peer net.IP) {
	typeAnnotation := ""
	if dnsType != "" {
		typeAnnotation = dnsType + " "
	}

	l.logWithHostInfo(peer, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(Faint)+"Ignoring %squery for %q from %s",
			typeAnnotation, name, hostInfo)
	})
}

// IgnoreDHCP prints information abound ignored DHCP requests.
func (l *Logger) IgnoreDHCP(dhcpType string, peer net.IP) {
	l.logWithHostInfo(peer, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(Faint)+"Ignoring DHCP %s request from %s", dhcpType, hostInfo)
	})
}

// Errorf prints errors.
func (l *Logger) Errorf(format string, a ...interface{}) {
	l.logf(os.Stderr, l.styleAndPrefix(Bold, FgRed)+format, a...)
}

// Fatalf prints fatal errors and quits the application without shutdown.
func (l *Logger) Fatalf(format string, a ...interface{}) {
	l.logf(os.Stderr, l.styleAndPrefix(Bold, FgRed)+format, a...)
	os.Exit(1)
}

// Flush blocks until all log messages are printed.
func (l *Logger) Flush() {
	l.baseLogger.wg.Wait()
}

func (l *Logger) logWithHostInfo(peer net.IP, logString func(hostInfo string) string) {
	l.baseLogger.wg.Add(1)

	log := func() {
		hostInfo := ""
		if !l.NoHostInfo {
			hostInfo = l.HostInfoCache.HostInfoAnnotation(peer)
		}

		l.logf(os.Stdout, logString(hostInfo))

		l.baseLogger.wg.Done()
	}

	if l.NoHostInfo {
		log()
	} else {
		go log()
	}
}

func (l *Logger) logf(w io.Writer, format string, a ...interface{}) {
	if l.PrintTimestamps {
		format = fmt.Sprintf("%s%s%s %s", l.style(Faint), time.Now().Format("15:04:05"), l.style(Reset), format)
	}

	l.baseLogger.wg.Add(1)

	go func() {
		fmt.Fprintf(w, format+l.style(Reset)+"\n", a...)
		l.baseLogger.wg.Done()
	}()
}

func (l *Logger) styleAndPrefix(attrs ...Attribute) string {
	if l.Prefix == "" {
		return l.style(attrs...)
	}

	return fmt.Sprintf("%s%s[%s]%s%s ", l.style(attrs...), l.style(Bold), l.Prefix, l.style(Reset), l.style(attrs...))
}
