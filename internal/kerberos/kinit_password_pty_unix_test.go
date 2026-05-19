//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package kerberos

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultKinitPasswordRunnerUsesPTY(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "kinit")
	if err := os.WriteFile(script, []byte(`#!/bin/sh
if [ ! -t 0 ]; then
  echo no-tty >&2
  exit 7
fi
IFS= read -r password
if [ "$password" != "secret" ]; then
  echo bad-password >&2
  exit 8
fi
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := defaultKinitPasswordRunner(5*time.Second, "user@REALM", nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
}
