package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if !strings.Contains(string(out), "Configuration saved to ") || !strings.Contains(string(out), "server = upstream.proxy.com:55112") {
		t.Fatalf("save output missing confirmation or config:\n%s", out)
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
		"PXGO_KEYRING_PLAINTEXT=1",
		"PXGO_KEYRING_FILE="+keyring,
		"PXGO_PASSWORD=upstream-pass",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("password action failed: %v\n%s", err, out)
	}
	cmd = exec.Command(bin, "--client_username=client-user", "--client-password")
	cmd.Env = append(os.Environ(),
		"PXGO_KEYRING_PLAINTEXT=1",
		"PXGO_KEYRING_FILE="+keyring,
		"PXGO_CLIENT_PASSWORD=client-pass",
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
	cmd, out, _ := startPxProcess(t, bin, "--port="+fmt.Sprint(port), "--listen=127.0.0.1")
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

func TestCLINetworkListenSpecificIP(t *testing.T) {
	if os.Getenv("CI") == "true" && os.Getenv("RUN_LOOPBACK_ALIAS_TESTS") != "1" {
		t.Skip("loopback aliases are environment-specific in CI")
	}
	bin := buildPx(t)
	port := freePort(t)
	cmd, out, cancel := startPxProcess(t, bin, "--port="+fmt.Sprint(port), "--listen=127.0.0.2")
	defer cancel()
	_ = cmd
	if err := dialTCP("127.0.0.2", port); err != nil {
		t.Fatalf("specific listen address did not accept connections: %v\n%s", err, out.String())
	}
	if err := dialTCP("127.0.0.1", port); err == nil {
		t.Fatalf("proxy accepted 127.0.0.1 despite --listen=127.0.0.2\n%s", out.String())
	}
}

func TestCLINetworkGatewayAllowRejectsDisallowedClient(t *testing.T) {
	bin := buildPx(t)
	port := freePort(t)
	cmd, out, cancel := startPxProcess(t, bin, "--port="+fmt.Sprint(port), "--gateway", "--allow=10.0.*.*")
	defer cancel()
	_ = cmd
	resp, err := http.Get("http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port)) + "/")
	if err != nil {
		t.Fatalf("request failed: %v\n%s", err, out.String())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%s want 403\n%s", resp.Status, out.String())
	}
}

func TestCLINetworkHostonlyAllowsLocalProxying(t *testing.T) {
	bin := buildPx(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hostonly ok")
	}))
	defer upstream.Close()
	port := freePort(t)
	cmd, out, cancel := startPxProcess(t, bin, "--port="+fmt.Sprint(port), "--hostonly")
	defer cancel()
	_ = cmd
	resp, err := cliProxyClient(port).Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied request failed: %v\n%s", err, out.String())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "hostonly ok" {
		t.Fatalf("body=%q status=%s\n%s", data, resp.Status, out.String())
	}
}

func TestCLINetworkNoProxyBypassesConfiguredProxy(t *testing.T) {
	bin := buildPx(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct ok")
	}))
	defer upstream.Close()
	port := freePort(t)
	cmd, out, cancel := startPxProcess(t, bin,
		"--port="+fmt.Sprint(port),
		"--proxy=127.0.0.1:1",
		"--noproxy=127.0.0.1",
	)
	defer cancel()
	_ = cmd
	resp, err := cliProxyClient(port).Get(upstream.URL)
	if err != nil {
		t.Fatalf("proxied request failed: %v\n%s", err, out.String())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "direct ok" {
		t.Fatalf("body=%q status=%s\n%s", data, resp.Status, out.String())
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
	cmd.Env = append(os.Environ(), "PXGO_PASSWORD=12345")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("self-test auth failed: %v\n%s", err, out)
	}
}

func buildPx(t *testing.T) string {
	t.Helper()
	name := "pxgo"
	if runtime.GOOS == "windows" {
		name = "pxgo.exe"
	}
	bin := filepath.Join(t.TempDir(), name)
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

func startPxProcess(t *testing.T, bin string, args ...string) (*exec.Cmd, *strings.Builder, context.CancelFunc) {
	t.Helper()
	port := ""
	listen := "127.0.0.1"
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "--port="); ok {
			port = value
			continue
		}
		if value, ok := strings.CutPrefix(arg, "--listen="); ok && value != "" {
			listen = value
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	out := &strings.Builder{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	if port != "" {
		waitForAddr(t, listen, mustAtoi(t, port))
	}
	return cmd, out, cancel
}

func waitForAddr(t *testing.T, host string, port int) {
	t.Helper()
	addr := net.JoinHostPort(host, fmt.Sprint(port))
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

func cliProxyClient(port int) *http.Client {
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(port))}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}, Timeout: 10 * time.Second}
}

func dialTCP(host string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 300*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	var out int
	if _, err := fmt.Sscanf(value, "%d", &out); err != nil {
		t.Fatalf("bad integer %q: %v", value, err)
	}
	return out
}
