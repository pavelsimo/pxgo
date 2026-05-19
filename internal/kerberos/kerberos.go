package kerberos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	CheckInterval = 300 * time.Second
	RetryInterval = 60 * time.Second
	RenewalMargin = 10 * time.Minute
	kinitCommand  = "kinit"
	klistCommand  = "klist"
)

type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

var (
	commandRunner       = defaultCommandRunner
	kinitPasswordRunner = defaultKinitPasswordRunner
)

type Manager struct {
	Principal    string
	PasswordFunc func() *string
	CCacheName   string
	Env          map[string]string
	IsHeimdal    bool

	TicketExpiry time.Time
	NextCheck    time.Time
	Backoff      time.Duration

	mu sync.Mutex

	KinitWithPasswordFunc func() bool
	KinitRenewFunc        func() bool
	KlistValidFunc        func() bool
}

func New(principal string, passwordFunc func() *string, isHeimdal bool) *Manager {
	ccache := "FILE:" + filepath.Join(os.TempDir(), "krb5cc_px_"+itoa(os.Getpid()))
	_ = os.Setenv("KRB5CCNAME", ccache)
	env := map[string]string{}
	for _, item := range os.Environ() {
		k, v, ok := strings.Cut(item, "=")
		if ok {
			env[k] = v
		}
	}
	env["KRB5CCNAME"] = ccache
	m := &Manager{
		Principal:    principal,
		PasswordFunc: passwordFunc,
		CCacheName:   ccache,
		Env:          env,
		IsHeimdal:    isHeimdal,
	}
	m.KinitWithPasswordFunc = m.KinitWithPassword
	m.KinitRenewFunc = m.KinitRenew
	m.KlistValidFunc = m.KlistValid
	return m
}

func defaultCommandRunner(timeout time.Duration, args []string, env map[string]string, stdin string) (commandResult, error) {
	if len(args) == 0 {
		return commandResult{}, errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204 -- callers pass fixed Kerberos command names with controlled arguments.
	if env != nil {
		cmd.Env = envSlice(env)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.Output()
	result := commandResult{Stdout: string(out)}
	if ee := new(exec.ExitError); errors.As(err, &ee) {
		result.Stderr = string(ee.Stderr)
		result.ExitCode = ee.ExitCode()
		return result, nil
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return result, context.DeadlineExceeded
		}
		return result, err
	}
	return result, nil
}

func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	n := i
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}

func (m *Manager) Check(force bool) *bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if !force && !m.NextCheck.IsZero() && now.Before(m.NextCheck) {
		return nil
	}
	if !m.TicketExpiry.IsZero() && now.Before(m.TicketExpiry.Add(-RenewalMargin)) {
		if m.KlistValidFunc() {
			next := now.Add(CheckInterval)
			renewAt := m.TicketExpiry.Add(-RenewalMargin)
			if next.After(renewAt) {
				next = renewAt
			}
			m.NextCheck = next
			return nil
		}
	}
	if m.Backoff > 0 && !force {
		m.NextCheck = now.Add(m.Backoff)
		m.Backoff = 0
		return nil
	}
	if !m.TicketExpiry.IsZero() && now.Before(m.TicketExpiry) && m.KinitRenewFunc() {
		ok := true
		return &ok
	}
	ok := m.KinitWithPasswordFunc()
	return &ok
}

func (m *Manager) ParseAndSetExpiry(klistOutput string) {
	expiry, ok := ParseExpiry(klistOutput, m.IsHeimdal)
	if !ok {
		m.TicketExpiry = time.Time{}
		m.NextCheck = time.Now().Add(RetryInterval)
		return
	}
	m.TicketExpiry = expiry
	next := time.Now().Add(CheckInterval)
	renewAt := expiry.Add(-RenewalMargin)
	if next.After(renewAt) {
		next = renewAt
	}
	m.NextCheck = next
}

func DetectHeimdal() bool {
	result, err := commandRunner(5*time.Second, []string{klistCommand, "--version"}, nil, "")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(result.Stdout+result.Stderr), "heimdal")
}

func (m *Manager) KinitWithPassword() bool {
	password := m.PasswordFunc()
	if password == nil {
		return false
	}
	result, err := kinitPasswordRunner(30*time.Second, m.Principal, m.Env, *password)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			m.Backoff = RetryInterval
		case errors.Is(err, exec.ErrNotFound) || os.IsNotExist(err):
			m.Backoff = CheckInterval
		default:
			m.Backoff = RetryInterval
		}
		return false
	}
	if result.ExitCode != 0 {
		errText := strings.ToLower(result.Stderr)
		switch {
		case strings.Contains(errText, "expired"),
			strings.Contains(errText, "revoked"),
			strings.Contains(errText, "preauthentication failed"),
			strings.Contains(errText, "password incorrect"),
			strings.Contains(errText, "not found"),
			strings.Contains(errText, "unknown"),
			strings.Contains(errText, "skew"):
			m.Backoff = CheckInterval
		default:
			m.Backoff = RetryInterval
		}
		return false
	}
	m.Backoff = 0
	m.UpdateExpiry()
	return true
}

func (m *Manager) KinitRenew() bool {
	result, err := commandRunner(5*time.Second, []string{kinitCommand, "-R"}, m.Env, "")
	if err != nil || result.ExitCode != 0 {
		return false
	}
	m.UpdateExpiry()
	return true
}

func (m *Manager) KlistValid() bool {
	flag := "-s"
	if m.IsHeimdal {
		flag = "--test"
	}
	result, err := commandRunner(5*time.Second, []string{klistCommand, flag}, m.Env, "")
	if err != nil {
		return false
	}
	stderr := strings.ToLower(result.Stderr)
	if strings.Contains(stderr, "unrecognized") || strings.Contains(stderr, "unknown") || strings.Contains(stderr, "illegal") {
		return m.KlistParseValid()
	}
	return result.ExitCode == 0
}

func (m *Manager) RunKlist() (string, bool) {
	result, err := commandRunner(5*time.Second, []string{klistCommand}, m.Env, "")
	if err != nil || result.ExitCode != 0 {
		return "", false
	}
	return result.Stdout, true
}

func (m *Manager) KlistParseValid() bool {
	output, ok := m.RunKlist()
	return ok && strings.Contains(strings.ToLower(output), "krbtgt")
}

func (m *Manager) UpdateExpiry() {
	output, ok := m.RunKlist()
	if !ok {
		m.TicketExpiry = time.Time{}
		m.NextCheck = time.Now().Add(RetryInterval)
		return
	}
	m.ParseAndSetExpiry(output)
}

func ParseExpiry(output string, heimdal bool) (time.Time, bool) {
	if heimdal {
		return parseHeimdal(output)
	}
	return parseMIT(output)
}

func parseMIT(output string) (time.Time, bool) {
	re := regexp.MustCompile(`(?m)^\s*\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}\s+(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})\s+krbtgt/`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		return time.Time{}, false
	}
	for _, layout := range []string{"1/2/2006 15:04:05", "1/2/06 15:04:05"} {
		if t, err := time.ParseInLocation(layout, matches[1], time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseHeimdal(output string) (time.Time, bool) {
	re := regexp.MustCompile(`(?m)^\s*[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+krbtgt/`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("Jan 2 15:04:05 2006", matches[1], time.Local)
	return t, err == nil
}

func (m *Manager) Cleanup() {
	path := strings.TrimPrefix(m.CCacheName, "FILE:")
	if path != m.CCacheName {
		_ = os.Remove(path)
	}
}
