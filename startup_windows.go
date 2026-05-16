//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func installStartup(cmd string, force bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !force {
		if _, _, err := key.GetStringValue("Px"); err == nil {
			return nil
		} else if !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return key.SetExpandStringValue("Px", cmd)
}

func uninstallStartup() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if _, _, err := key.GetStringValue("Px"); errors.Is(err, registry.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return key.DeleteValue("Px")
}
