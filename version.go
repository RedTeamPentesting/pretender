package main

import (
	"fmt"
	"runtime/debug"
	"time"
)

const (
	banner          = "Pretender by RedTeam Pentesting"
	shortCommitSize = 10
)

var version = "" // this variable can be set during compilation

func buildSettingReader() func(string) (string, bool) {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return func(string) (string, bool) { return "", false }
	}

	return func(key string) (string, bool) {
		for _, setting := range buildInfo.Settings {
			if setting.Key == key {
				return setting.Value, true
			}
		}

		return "", false
	}
}

func shortVersion() string {
	fallback := version
	if fallback == "" {
		fallback = "(unknown version)"
	}

	readBuildSetting := buildSettingReader()

	commit, ok := readBuildSetting("vcs.revision")
	if !ok {
		return fmt.Sprintf("%s %s", banner, fallback)
	}

	if len(commit) > shortCommitSize {
		commit = commit[:shortCommitSize]
	}

	dirty, _ := readBuildSetting("vcs.modified")

	if version == "" {
		vcs, ok := readBuildSetting("vcs")
		if ok {
			vcs = " " + vcs
		}

		dirtySuffix := ""
		if dirty == "true" {
			dirtySuffix = " (dirty)"
		}

		return fmt.Sprintf("%s built from%s commit %s%s", banner, vcs, commit, dirtySuffix)
	}

	if dirty == "true" {
		return fmt.Sprintf("%s %s", banner, version)
	}

	return fmt.Sprintf("%s %s-%s", banner, version, commit)
}

func longVersion() string { // nolint:cyclop
	fallback := version
	if fallback == "" {
		fallback = "(unknown version)"
	}

	banner := banner
	if version != "" {
		banner = fmt.Sprintf("%s %s", banner, version)
	}

	readBuildSetting := buildSettingReader()

	version = "built"

	cgo, ok := readBuildSetting("CGO_ENABLED")
	if ok {
		if cgo == "1" {
			version += " with CGO"
		} else {
			version += " without CGO"
		}
	}

	vcs, ok := readBuildSetting("vcs")
	if !ok {
		return fmt.Sprintf("%s %s", banner, fallback)
	}

	version = fmt.Sprintf("%s from %s", version, vcs)

	commit, ok := readBuildSetting("vcs.revision")
	if !ok {
		return fmt.Sprintf("%s %s", banner, fallback)
	}

	version = fmt.Sprintf("%s commit %s", version, commit)

	timeStamp, ok := readBuildSetting("vcs.time")
	if ok {
		t, err := time.Parse(time.RFC3339, timeStamp)
		if err == nil {
			version = fmt.Sprintf("%s#%v", version, t.Format("2006-01-02"))
		}
	}

	dirty, ok := readBuildSetting("vcs.modified")
	if ok && dirty == "true" {
		version = fmt.Sprintf("%s (dirty)", version)
	}

	return fmt.Sprintf("%s %s", banner, version)
}
