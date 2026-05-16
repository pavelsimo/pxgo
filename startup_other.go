//go:build !windows

package main

import "errors"

func installStartup(_ string, _ bool) error {
	return errors.New("--install is only supported on Windows")
}

func uninstallStartup() error {
	return errors.New("--uninstall is only supported on Windows")
}
