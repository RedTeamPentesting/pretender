package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// escape is the ANSI escape sequence.
const escape = "\x1b"

// attribute represents a style.
type attribute int

// Base attributes.
const (
	reset attribute = iota
	bold
	faint
)

// Foreground text colors.
const (
	fgRed attribute = iota + 31
	fgGreen
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

func (l *Logger) style(attrs ...attribute) string {
	if l.NoColor {
		return ""
	}

	s := ""
	for _, a := range attrs {
		s += fmt.Sprintf("%s[%dm", escape, a)
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

	l.logf(os.Stdout, l.styleAndPrefix(faint)+format, a...)
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
		return fmt.Sprintf(l.styleAndPrefix(fgGreen)+"%q%s queried by %s", name, typeAnnotation, hostInfo)
	})
}

// IgnoreDNS prints information abound ignored DNS queries.
func (l *Logger) IgnoreDNS(name string, dnsType string, peer net.IP) {
	typeAnnotation := ""
	if dnsType != "" {
		typeAnnotation = dnsType + " "
	}

	l.logWithHostInfo(peer, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(faint)+"Ignoring %squery for %q from %s",
			typeAnnotation, name, hostInfo)
	})
}

// IgnoreDHCP prints information abound ignored DHCP requests.
func (l *Logger) IgnoreDHCP(dhcpType string, peer peerInfo) {
	l.logWithHostInfo(peer.IP, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(faint)+"Ignoring DHCP %s request from %s", dhcpType, hostInfo)
	})
}

// Errorf prints errors.
func (l *Logger) Errorf(format string, a ...interface{}) {
	l.logf(os.Stderr, l.styleAndPrefix(bold, fgRed)+format, a...)
}

// Fatalf prints fatal errors and quits the application without shutdown.
func (l *Logger) Fatalf(format string, a ...interface{}) {
	l.logf(os.Stderr, l.styleAndPrefix(bold, fgRed)+format, a...)
	os.Exit(1)
}

// Flush blocks until all log messages are printed.
func (l *Logger) Flush() {
	l.baseLogger.wg.Wait()
}

func (l *Logger) logWithHostInfo(peer net.IP, logString func(hostInfo string) string) {
	l.baseLogger.wg.Add(1)

	log := func() {
		hostInfo := peer.String()
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
		format = fmt.Sprintf("%s%s%s %s", l.style(faint), time.Now().Format("15:04:05"), l.style(reset), format)
	}

	l.baseLogger.wg.Add(1)

	go func() {
		fmt.Fprintf(w, format+l.style(reset)+"\n", a...)
		l.baseLogger.wg.Done()
	}()
}

func (l *Logger) styleAndPrefix(attrs ...attribute) string {
	if l.Prefix == "" {
		return l.style(attrs...)
	}

	return fmt.Sprintf("%s%s[%s]%s%s ", l.style(attrs...), l.style(bold), l.Prefix, l.style(reset), l.style(attrs...))
}

func styled(text string, disableStyle bool, styles ...attribute) string {
	if disableStyle {
		return text
	}

	strStyles := make([]string, 0, len(styles))
	for _, s := range styles {
		strStyles = append(strStyles, strconv.Itoa(int(s)))
	}

	return fmt.Sprintf("%s[%sm%s%s[%dm", escape, strings.Join(strStyles, ";"), text, escape, reset)
}
