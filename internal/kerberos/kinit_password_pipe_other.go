//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package kerberos

import "time"

func defaultKinitPasswordRunner(timeout time.Duration, principal string, env map[string]string, password string) (commandResult, error) {
	return commandRunner(timeout, []string{kinitCommand, principal}, env, password+"\n")
}
