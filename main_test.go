package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/debug"
)

func TestSetupDebugCreatesCWDLog(t *testing.T) {
	debug.ResetForTest()
	tmp := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		debug.ResetForTest()
		_ = os.Chdir(oldwd)
	})
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if err := setupDebug(config.Config{Log: config.LogCWD}); err != nil {
		t.Fatal(err)
	}
	debug.Dprint("debug enabled")
	if _, err := os.Stat(filepath.Join(tmp, "debug-main.log")); err != nil {
		t.Fatal(err)
	}
}

func TestListenForClientUsesFirstConcreteAddress(t *testing.T) {
	tests := map[string]string{
		"":                        "127.0.0.1",
		"0.0.0.0":                 "127.0.0.1",
		"127.0.0.1, 127.0.0.2":    "127.0.0.1",
		" 127.0.0.2 , 127.0.0.1 ": "127.0.0.2",
	}
	for listen, want := range tests {
		if got := listenForClient(listen); got != want {
			t.Fatalf("%q got %q want %q", listen, got, want)
		}
	}
}

func TestCLISave(t *testing.T) {
	bin := buildPx(t)
	path := filepath.Join(t.TempDir(), "custom", "pxgo.ini")
	cmd := exec.Command(bin,
		"--save",
		"--config="+path,
		"--server=upstream.proxy.com:55112",
		"--port=3131",
		"--gateway=1",
		"--hostonly=1",
		"--auth=BASIC",
		"--username=randomuser",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"server = upstream.proxy.com:55112", "port = 3131", "listen = ", "auth = BASIC", "username = randomuser"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
}

func TestCLIPasswordActionsUsePlaintextKeyring(t *testing.T) {
	bin := buildPx(t)
	keyring := filepath.Join(t.TempDir(), "keyring.json")
	cmd := exec.Command(bin, "--username=upstream-user", "--password")
	cmd.Env = append(os.Environ(),
		"PX_KEYRING_PLAINTEXT=1",
		"PX_KEYRING_FILE="+keyring,
		"PX_PASSWORD=upstream-pass",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("password action failed: %v\n%s", err, out)
	}
	cmd = exec.Command(bin, "--client_username=client-user", "--client-password")
	cmd.Env = append(os.Environ(),
		"PX_KEYRING_PLAINTEXT=1",
		"PX_KEYRING_FILE="+keyring,
		"PX_CLIENT_PASSWORD=client-pass",
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client password action failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"upstream-user", "upstream-pass", "client-user", "client-pass"} {
		if !strings.Contains(text, want) {
			t.Fatalf("keyring missing %q:\n%s", want, text)
		}
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	bin := buildPx(t)
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, out)
		}
		if !strings.Contains(string(out), "Usage:") || !strings.Contains(string(out), "--proxy") {
			t.Fatalf("unexpected help:\n%s", out)
		}
	}
	cmd := exec.Command(bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatalf("unexpected version: %s", out)
	}
}

func TestCLIQuitStopsRunningProxy(t *testing.T) {
	bin := buildPx(t)
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--port="+fmt.Sprint(port), "--listen=127.0.0.1")
	out := &strings.Builder{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	waitForPort(t, port)
	quit := exec.Command(bin, "--port="+fmt.Sprint(port), "--quit")
	quitOut, err := quit.CombinedOutput()
	if err != nil {
		t.Fatalf("quit failed: %v\n%s\nserver:\n%s", err, quitOut, out.String())
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server exited with %v\n%s", err, out.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop after --quit")
	}
}

func TestCLISelfTestAgainstLocalHTTP(t *testing.T) {
	bin := buildPx(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
	}))
	defer upstream.Close()
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--port="+fmt.Sprint(port), "--test=all:"+upstream.URL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self-test failed: %v\n%s", err, out)
	}
}

func TestCLISelfTestSingleURLUsesGETOnly(t *testing.T) {
	bin := buildPx(t)
	var methods []string
	var paths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--port="+fmt.Sprint(port), "--test="+upstream.URL+"/check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("single-url self-test failed: %v\n%s", err, out)
	}
	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("methods=%#v, want single GET", methods)
	}
	if len(paths) != 1 || paths[0] != "/check" {
		t.Fatalf("paths=%#v, want exact /check", paths)
	}
}

func TestCLISelfTestAuthPassesClientCredentials(t *testing.T) {
	bin := buildPx(t)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test:12345"))
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != wantAuth {
			w.Header().Set("Proxy-Authenticate", `Basic realm="PxClient"`)
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"--port="+fmt.Sprint(port),
		"--proxy="+parentURL.Host,
		"--auth=BASIC",
		"--username=test",
		"--test-auth",
		"--test=all:http://target.invalid",
	)
	cmd.Env = append(os.Environ(), "PX_PASSWORD=12345")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self-test auth failed: %v\n%s", err, out)
	}
}

func buildPx(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pxgo")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s did not open", addr)
}
