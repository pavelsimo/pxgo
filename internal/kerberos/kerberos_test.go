package kerberos

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const mitKlistOutput = `Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting       Expires              Service principal
03/10/2026 08:00:00  03/10/2026 18:00:00  krbtgt/REALM@REALM
        renew until 03/17/2026 08:00:00
`

const mitKlistOutput2DigitYear = `Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting     Expires            Service principal
03/10/26 08:00:00  03/10/26 18:00:00  krbtgt/REALM@REALM
        renew until 03/17/26 08:00:00
`

const mitKlistOutputSingleDigit = `Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting       Expires              Service principal
3/10/2026 08:00:00   3/10/2026 18:00:00   krbtgt/REALM@REALM
        renew until 3/17/2026 08:00:00
`

const heimdalKlistOutput = `Credentials cache: FILE:/tmp/krb5cc_px_12345
        Principal: user@REALM

  Issued                Expires               Principal
Mar 10 08:00:00 2026  Mar 10 18:00:00 2026  krbtgt/REALM@REALM
`

func makeManager() *Manager {
	password := "secret"
	return New("user@REALM", func() *string { return &password }, false)
}

func TestInit(t *testing.T) {
	mgr := makeManager()
	if got := os.Getenv("KRB5CCNAME"); got != mgr.CCacheName {
		t.Fatalf("KRB5CCNAME=%q want %q", got, mgr.CCacheName)
	}
	if mgr.Env["KRB5CCNAME"] != mgr.CCacheName {
		t.Fatalf("env missing ccache")
	}
	if !strings.Contains(mgr.CCacheName, "krb5cc_px_") {
		t.Fatalf("bad ccache name %q", mgr.CCacheName)
	}
	if !mgr.TicketExpiry.IsZero() || !mgr.NextCheck.IsZero() || mgr.Backoff != 0 {
		t.Fatalf("unexpected initial state")
	}
}

func TestParseExpiryMITFormats(t *testing.T) {
	want, _ := time.ParseInLocation("01/02/2006 15:04:05", "03/10/2026 18:00:00", time.Local)
	for name, output := range map[string]string{
		"mit":          mitKlistOutput,
		"two-digit":    mitKlistOutput2DigitYear,
		"single-digit": mitKlistOutputSingleDigit,
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := ParseExpiry(output, false)
			if !ok {
				t.Fatal("parse failed")
			}
			if !got.Equal(want) {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func TestParseExpiryHeimdal(t *testing.T) {
	want, _ := time.ParseInLocation("01/02/2006 15:04:05", "03/10/2026 18:00:00", time.Local)
	got, ok := ParseExpiry(heimdalKlistOutput, true)
	if !ok {
		t.Fatal("parse failed")
	}
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseExpiryFailureSetsNextCheck(t *testing.T) {
	mgr := makeManager()
	mgr.ParseAndSetExpiry("Ticket cache only")
	if !mgr.TicketExpiry.IsZero() {
		t.Fatal("expected zero ticket expiry")
	}
	if !mgr.NextCheck.After(time.Now()) {
		t.Fatal("expected future next check")
	}
}

func TestCheckFastPath(t *testing.T) {
	mgr := makeManager()
	mgr.NextCheck = time.Now().Add(time.Hour)
	called := false
	mgr.KinitWithPasswordFunc = func() bool {
		called = true
		return true
	}
	if got := mgr.Check(false); got != nil {
		t.Fatalf("got %v", *got)
	}
	if called {
		t.Fatal("kinit should not be called")
	}
}

func TestCheckNearExpiryRenewalAndFallback(t *testing.T) {
	mgr := makeManager()
	mgr.TicketExpiry = time.Now().Add(5 * time.Minute)
	mgr.KlistValidFunc = func() bool { return false }
	renewed := false
	mgr.KinitRenewFunc = func() bool {
		renewed = true
		return false
	}
	kinit := false
	mgr.KinitWithPasswordFunc = func() bool {
		kinit = true
		return true
	}
	got := mgr.Check(false)
	if got == nil || !*got || !renewed || !kinit {
		t.Fatalf("renewed=%v kinit=%v got=%v", renewed, kinit, got)
	}
}

func TestCheckHealthyTicketUsesKlistFastValidation(t *testing.T) {
	mgr := makeManager()
	mgr.TicketExpiry = time.Now().Add(time.Hour)
	validated := false
	mgr.KlistValidFunc = func() bool {
		validated = true
		return true
	}
	mgr.KinitWithPasswordFunc = func() bool {
		t.Fatal("kinit should not run for a healthy valid ticket")
		return false
	}
	if got := mgr.Check(false); got != nil {
		t.Fatalf("got %v", *got)
	}
	if !validated || !mgr.NextCheck.After(time.Now()) {
		t.Fatalf("validated=%v next=%v", validated, mgr.NextCheck)
	}
}

func TestBackoffPreventsKinitOnce(t *testing.T) {
	mgr := makeManager()
	mgr.Backoff = CheckInterval
	calls := 0
	mgr.KinitWithPasswordFunc = func() bool {
		calls++
		return true
	}
	if got := mgr.Check(false); got != nil {
		t.Fatalf("got %v", *got)
	}
	if calls != 0 || mgr.Backoff != 0 || !mgr.NextCheck.After(time.Now()) {
		t.Fatalf("calls=%d backoff=%s next=%v", calls, mgr.Backoff, mgr.NextCheck)
	}
	mgr.NextCheck = time.Time{}
	got := mgr.Check(false)
	if got == nil || !*got || calls != 1 {
		t.Fatalf("calls=%d got=%v", calls, got)
	}
}

func TestForceBypassesBackoff(t *testing.T) {
	mgr := makeManager()
	mgr.Backoff = CheckInterval
	calls := 0
	mgr.KinitWithPasswordFunc = func() bool {
		calls++
		return true
	}
	got := mgr.Check(true)
	if got == nil || !*got || calls != 1 {
		t.Fatalf("calls=%d got=%v", calls, got)
	}
}

func TestConcurrentThreadsWaitForRenewal(t *testing.T) {
	mgr := makeManager()
	mgr.NextCheck = time.Time{}
	mgr.KinitWithPasswordFunc = func() bool {
		time.Sleep(150 * time.Millisecond)
		mgr.TicketExpiry = time.Now().Add(time.Hour)
		mgr.NextCheck = time.Now().Add(CheckInterval)
		return true
	}
	var wg sync.WaitGroup
	results := make([]*bool, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0] = mgr.Check(false)
	}()
	time.Sleep(25 * time.Millisecond)
	go func() {
		defer wg.Done()
		results[1] = mgr.Check(false)
	}()
	wg.Wait()
	if results[0] == nil || !*results[0] {
		t.Fatalf("renewer result=%v", results[0])
	}
	if results[1] != nil {
		t.Fatalf("waiter result=%v", *results[1])
	}
}

func TestDetectHeimdal(t *testing.T) {
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		if !reflect.DeepEqual(args, []string{"klist", "--version"}) {
			t.Fatalf("args=%#v", args)
		}
		return commandResult{Stdout: "klist (Heimdal 7.8.0)"}, nil
	})
	if !DetectHeimdal() {
		t.Fatal("expected heimdal")
	}
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		return commandResult{}, exec.ErrNotFound
	})
	if DetectHeimdal() {
		t.Fatal("missing klist should default to MIT/false")
	}
}

func TestKlistValidFlagsAndFallback(t *testing.T) {
	mgr := makeManager()
	var calls [][]string
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			return commandResult{ExitCode: 1, Stderr: "unrecognized option"}, nil
		}
		return commandResult{Stdout: "krbtgt/REALM@REALM"}, nil
	})
	if !mgr.KlistValid() {
		t.Fatal("fallback parse should validate")
	}
	if !reflect.DeepEqual(calls[0], []string{"klist", "-s"}) || !reflect.DeepEqual(calls[1], []string{"klist"}) {
		t.Fatalf("calls=%#v", calls)
	}
	mgr.IsHeimdal = true
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		if !reflect.DeepEqual(args, []string{"klist", "--test"}) {
			t.Fatalf("args=%#v", args)
		}
		return commandResult{}, nil
	})
	if !mgr.KlistValid() {
		t.Fatal("heimdal --test should validate")
	}
}

func TestRunKlistAndUpdateExpiry(t *testing.T) {
	mgr := makeManager()
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		return commandResult{Stdout: mitKlistOutput}, nil
	})
	output, ok := mgr.RunKlist()
	if !ok || !strings.Contains(output, "krbtgt") {
		t.Fatalf("output=%q ok=%v", output, ok)
	}
	mgr.UpdateExpiry()
	if mgr.TicketExpiry.IsZero() || mgr.NextCheck.IsZero() {
		t.Fatalf("expiry=%v next=%v", mgr.TicketExpiry, mgr.NextCheck)
	}
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		return commandResult{ExitCode: 1}, nil
	})
	if _, ok := mgr.RunKlist(); ok {
		t.Fatal("failed klist should return false")
	}
}

func TestKinitRenew(t *testing.T) {
	mgr := makeManager()
	var calls [][]string
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			if env["KRB5CCNAME"] != mgr.CCacheName {
				t.Fatalf("missing KRB5CCNAME in env")
			}
			return commandResult{}, nil
		}
		return commandResult{Stdout: mitKlistOutput}, nil
	})
	if !mgr.KinitRenew() {
		t.Fatal("renew should succeed")
	}
	if !reflect.DeepEqual(calls[0], []string{"kinit", "-R"}) || !reflect.DeepEqual(calls[1], []string{"klist"}) {
		t.Fatalf("calls=%#v", calls)
	}
}

func TestKinitWithPasswordCommandPaths(t *testing.T) {
	mgr := makeManager()
	var gotPrincipal string
	withCommandRunner(t, func(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
		if !reflect.DeepEqual(args, []string{"klist"}) {
			t.Fatalf("args=%#v", args)
		}
		return commandResult{Stdout: mitKlistOutput}, nil
	})
	withKinitPasswordRunner(t, func(timeout time.Duration, principal string, env map[string]string, password string) (commandResult, error) {
		gotPrincipal = principal
		if env["KRB5CCNAME"] != mgr.CCacheName {
			t.Fatalf("missing KRB5CCNAME in env")
		}
		if password != "secret" {
			t.Fatalf("password=%q", password)
		}
		return commandResult{}, nil
	})
	if !mgr.KinitWithPassword() {
		t.Fatal("kinit should succeed")
	}
	if mgr.Backoff != 0 || gotPrincipal != "user@REALM" {
		t.Fatalf("backoff=%s principal=%q", mgr.Backoff, gotPrincipal)
	}
	none := New("user@REALM", func() *string { return nil }, false)
	withKinitPasswordRunner(t, func(timeout time.Duration, principal string, env map[string]string, password string) (commandResult, error) {
		t.Fatal("command should not run without password")
		return commandResult{}, nil
	})
	if none.KinitWithPassword() {
		t.Fatal("kinit without password should fail")
	}
}

func TestKinitWithPasswordFailureBackoff(t *testing.T) {
	mgr := makeManager()
	for _, tc := range []struct {
		name    string
		result  commandResult
		err     error
		backoff time.Duration
	}{
		{"not-found", commandResult{}, exec.ErrNotFound, CheckInterval},
		{"timeout", commandResult{}, context.DeadlineExceeded, RetryInterval},
		{"wrong-password", commandResult{ExitCode: 1, Stderr: "Preauthentication failed"}, nil, CheckInterval},
		{"generic", commandResult{ExitCode: 1, Stderr: "KDC unreachable"}, nil, RetryInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr.Backoff = 0
			withKinitPasswordRunner(t, func(timeout time.Duration, principal string, env map[string]string, password string) (commandResult, error) {
				return tc.result, tc.err
			})
			if mgr.KinitWithPassword() {
				t.Fatal("expected failure")
			}
			if mgr.Backoff != tc.backoff {
				t.Fatalf("backoff=%s want %s", mgr.Backoff, tc.backoff)
			}
		})
	}
}

func TestCleanup(t *testing.T) {
	mgr := makeManager()
	path := filepath.Join(t.TempDir(), "krb5cc_px_test")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr.CCacheName = "FILE:" + path
	mgr.Cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ccache still exists")
	}
	mgr.CCacheName = "FILE:" + filepath.Join(t.TempDir(), "missing")
	mgr.Cleanup()
}

func withCommandRunner(t *testing.T, fn func(time.Duration, []string, map[string]string, string) (commandResult, error)) {
	t.Helper()
	old := commandRunner
	commandRunner = fn
	t.Cleanup(func() { commandRunner = old })
}

func withKinitPasswordRunner(t *testing.T, fn func(time.Duration, string, map[string]string, string) (commandResult, error)) {
	t.Helper()
	old := kinitPasswordRunner
	kinitPasswordRunner = fn
	t.Cleanup(func() { kinitPasswordRunner = old })
}
