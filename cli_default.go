//go:build !windows

package main

func enableVirtualTerminalProcessing() error {
	return nil // we only have to do this on Windows
}
