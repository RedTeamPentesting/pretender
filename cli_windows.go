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

	err = windows.SetConsoleMode(stdoutHandle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if err != nil {
		return fmt.Errorf("stdout: set console mode: %w", err)
	}

	stderrHandle := windows.Handle(os.Stderr.Fd())

	err = windows.GetConsoleMode(stderrHandle, &mode)
	if err != nil {
		return fmt.Errorf("stderr: get console mode: %w", err)
	}

	err = windows.SetConsoleMode(stderrHandle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	if err != nil {
		return fmt.Errorf("stderr: set console mode: %w", err)
	}

	return nil
}
