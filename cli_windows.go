//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func enableVirtualTerminalProcessing() error {
	var mode uint32

	stdoutHandle := windows.Handle(os.Stdout.Fd())

	err := windows.GetConsoleMode(stdoutHandle, &mode)
	if err != nil {
		return fmt.Errorf("stdout: get console mode: %w", err)
	}

	err = windows.SetConsoleMode(stdoutHandle,
		mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
	if err != nil {
		return fmt.Errorf(
			"set ENABLE_VIRTUAL_TERMINAL_PROCESSING and ENABLE_PROCESSED_OUTPUT: stdout: set console mode: %w", err)
	}

	stderrHandle := windows.Handle(os.Stderr.Fd())

	err = windows.GetConsoleMode(stderrHandle, &mode)
	if err != nil {
		return fmt.Errorf("stderr: get console mode: %w", err)
	}

	err = windows.SetConsoleMode(stderrHandle,
		mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
	if err != nil {
		return fmt.Errorf(
			"set ENABLE_VIRTUAL_TERMINAL_PROCESSING and ENABLE_PROCESSED_OUTPUT: stderr: set console mode: %w", err)
	}

	return nil
}

func enterSemiRawMode() (exitSemiRawMode func() error, err error) {
	stdinHandle := windows.Handle(os.Stdin.Fd())

	var oldState uint32

	err = windows.GetConsoleMode(stdinHandle, &oldState)
	if err != nil {
		return nil, fmt.Errorf("query stdin terminal state: %w", err)
	}

	raw := oldState &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT)
	raw |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT

	err = windows.SetConsoleMode(stdinHandle, raw)
	if err != nil {
		_ = windows.SetConsoleMode(stdinHandle, oldState)

		return nil, fmt.Errorf("set stdin terminal state: %w", err)
	}

	return func() error {
		return windows.SetConsoleMode(stdinHandle, oldState)
	}, nil
}
