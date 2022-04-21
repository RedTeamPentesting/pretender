package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
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
	HideIgnored     bool
	NoHostInfo      bool

	LogFile      *os.File
	logFileMutex sync.Mutex

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
	}, logFileEntry{
		Name:      name,
		Type:      l.Prefix,
		QueryType: dnsType,
		Source:    peer,
	})
}

// IgnoreDNS prints information abound ignored DNS queries.
func (l *Logger) IgnoreDNS(name string, dnsType string, peer net.IP) {
	if l.HideIgnored {
		return
	}

	typeAnnotation := ""
	if dnsType != "" {
		typeAnnotation = dnsType + " "
	}

	l.logWithHostInfo(peer, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(faint)+"ignoring %squery for %q from %s",
			typeAnnotation, name, hostInfo)
	}, logFileEntry{
		Name:      name,
		Type:      "DNS",
		QueryType: dnsType,
		Source:    peer,
		Ignored:   true,
	})
}

// IgnoreDHCP prints information abound ignored DHCP requests.
func (l *Logger) IgnoreDHCP(dhcpType string, peer peerInfo) {
	l.HostInfoCache.AddHostnamesForIP(peer.IP, peer.Hostnames)

	if l.HideIgnored {
		return
	}

	l.logWithHostInfo(peer.IP, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(faint)+"ignoring DHCP %s request from %s", dhcpType, hostInfo)
	}, logFileEntry{
		Source:  peer.IP,
		Ignored: true,
		Type:    "DHCP",
	})
}

// DHCP prints information abound answered DHCP requests in which an address is assined.
func (l *Logger) DHCP(dhcpType dhcpv6.MessageType, peer peerInfo, assignedAddress net.IP) {
	l.HostInfoCache.AddHostnamesForIP(peer.IP, peer.Hostnames)

	message := "responding to %s from %s by assigning "
	if dhcpType != dhcpv6.MessageTypeSolicit {
		message += "DNS server and "
	}

	message += "IPv6 %q"

	l.logWithHostInfo(peer.IP, func(hostInfo string) string {
		return fmt.Sprintf(l.styleAndPrefix()+l.style(faint)+message, dhcpType, peer, assignedAddress)
	}, logFileEntry{
		AssignedAddress: assignedAddress,
		QueryType:       dhcpType.String(),
		Source:          peer.IP,
		Type:            "DHCP",
	})
}

// Errorf prints errors.
func (l *Logger) Errorf(format string, a ...interface{}) {
	l.logf(stdErr, l.styleAndPrefix(bold, fgRed)+format, a...)
}

// Fatalf prints fatal errors and quits the application without shutdown.
func (l *Logger) Fatalf(format string, a ...interface{}) {
	l.logf(stdErr, l.styleAndPrefix(bold, fgRed)+format, a...)
	os.Exit(1)
}

// Flush blocks until all log messages are printed. Flush does not nessarily
// flush the log file.
func (l *Logger) Flush() {
	l.baseLogger.wg.Wait()
}

// Close performs a Flush() and closes and thereby flushes the log file if configured.
func (l *Logger) Close() {
	l.Flush()
	defer l.Flush()

	if l.LogFile != nil {
		l.logFileMutex.Lock()
		err := l.LogFile.Close()
		l.logFileMutex.Unlock()

		l.LogFile = nil

		if err != nil {
			l.Errorf("closing log file: %v", err)
			l.Flush()
		}
	}
}

func (l *Logger) logWithHostInfo(peer net.IP, logString func(hostInfo string) string, logEntry logFileEntry) {
	l.baseLogger.wg.Add(1)

	if logEntry.Time.IsZero() {
		logEntry.Time = time.Now()
	}

	log := func() {
		hostInfo := peer.String()

		if !l.NoHostInfo {
			infos := l.HostInfoCache.HostInfos(peer)
			if len(infos) != 0 {
				hostInfo = fmt.Sprintf("%s (%s)", peer, strings.Join(infos, ", "))
			}

			logEntry.SourceInfo = infos
		}

		if l.LogFile != nil {
			fileLogLine, err := json.Marshal(logEntry)
			if err != nil {
				l.Errorf("marshalling file log entry: %v", err)
			}

			l.logFileMutex.Lock()
			_, err = l.LogFile.Write(append(fileLogLine, byte('\n')))
			l.logFileMutex.Unlock()

			if err != nil {
				l.Errorf("logging to file: %w", err)
				l.LogFile = nil
			}
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

type logFileEntry struct {
	Name            string    `json:"name,omitempty"`
	AssignedAddress net.IP    `json:"assigned_addr,omitempty"`
	QueryType       string    `json:"query_type,omitempty"`
	Type            string    `json:"type"`
	Source          net.IP    `json:"source"`
	SourceInfo      []string  `json:"source_info"`
	Time            time.Time `json:"time"`
	Ignored         bool      `json:"ignored"`
}

func escapeFormatString(s string) string {
	return strings.ReplaceAll(s, "%", "%%")
}
