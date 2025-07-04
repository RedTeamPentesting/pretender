//go:build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func enableVirtualTerminalProcessing() error {
	return nil // we only have to do this on Windows
}

func enterSemiRawMode() (exitSemiRawMode func() error, err error) {
	fd := int(os.Stdin.Fd())

	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, fmt.Errorf("query stdin terminal state: %w", err)
	}

	oldTermios := *termios

	termios.Lflag &^= unix.ECHO | unix.ICANON

	err = unix.IoctlSetTermios(fd, ioctlWriteTermios, termios)
	if err != nil {
		return nil, fmt.Errorf("set stdin terminal state: %w", err)
	}

	return func() error {
		return unix.IoctlSetTermios(fd, ioctlWriteTermios, &oldTermios)
	}, nil
}
