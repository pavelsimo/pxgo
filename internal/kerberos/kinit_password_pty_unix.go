//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package kerberos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"

	"github.com/creack/pty"
)

func defaultKinitPasswordRunner(timeout time.Duration, principal string, env map[string]string, password string) (commandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, kinitCommand, principal) // #nosec G204 -- principal is a configured Kerberos principal, command name is fixed.
	if env != nil {
		cmd.Env = envSlice(env)
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return commandResult{}, err
	}

	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&output, ptmx)
		close(done)
	}()

	_, _ = io.WriteString(ptmx, password+"\n")
	err = cmd.Wait()
	_ = ptmx.Close()
	<-done

	result := commandResult{Stdout: output.String(), Stderr: output.String()}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return result, context.DeadlineExceeded
	}
	if ee := new(exec.ExitError); errors.As(err, &ee) {
		result.ExitCode = ee.ExitCode()
		return result, nil
	}
	if err != nil {
		return result, err
	}
	return result, nil
}
