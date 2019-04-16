// +build !windows,!darwin

package hsm

import (
	"os"
	"path/filepath"
)

// https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html

var globalSettingFolder string

func init() {
	if os.Getenv("XDG_CONFIG_HOME") != "" {
		globalSettingFolder = os.Getenv("XDG_CONFIG_HOME")
	} else {
		globalSettingFolder = filepath.Join(os.Getenv("HOME"), ".config")
	}
}
