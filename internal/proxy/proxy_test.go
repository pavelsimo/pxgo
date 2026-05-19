package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/go-ntlmssp"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/kerberos"
	"github.com/pavelsimo/pxgo/internal/wproxy"
)

func startTestProxy(t *testing.T, cfg config.Config) *Server {
	t.Helper()
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1"
	}
	cfg.Port = 0
	if cfg.SockTimeout == 0 {
		cfg.SockTimeout = 5
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Start() }()
	deadline := time.Now().Add(5 * time.Second)
	for s.Port() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Port() == 0 {
		t.Fatal("proxy did not start")
	}
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
		select {
		case err := <-errc:
			if err != nil {
				t.Logf("proxy exit: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("proxy did not stop")
		}
	})
	return s
}

func proxyClient(t *testing.T, port int) *http.Client {
	t.Helper()
	u, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}, Timeout: 20 * time.Second}
}

func TestHTTPProxyMethods(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, string(body))
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, upstream.URL+"/"+strings.ToLower(method), strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), method) {
				t.Fatalf("status=%s body=%q", resp.Status, data)
			}
		})
	}
}

func TestUserAgentOverride(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.UserAgent())
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.UserAgent = "PxGoTest/1.0"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("User-Agent", "client-agent")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "PxGoTest/1.0" {
		t.Fatalf("user-agent=%q", data)
	}
}

func TestSockTimeoutBoundsSlowUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "too late")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.SockTimeout = 0.05
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for slow upstream, got %s", resp.Status)
	}
}

func TestConnectProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure ok")
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "secure ok" {
		t.Fatalf("body=%q", data)
	}
}

func TestConnectThroughSOCKS5PACProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "socks connect ok")
	}))
	defer upstream.Close()
	socksAddr := startTestSOCKS5(t)
	pacPath := filepath.Join(t.TempDir(), "socks.pac")
	if err := os.WriteFile(pacPath, []byte(fmt.Sprintf(`function FindProxyForURL(url, host) { return "SOCKS5 %s"; }`, socksAddr)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "socks connect ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestHTTPThroughSOCKS5PACProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "socks http ok")
	}))
	defer upstream.Close()
	socksAddr := startTestSOCKS5(t)
	pacPath := filepath.Join(t.TempDir(), "socks-http.pac")
	if err := os.WriteFile(pacPath, []byte(fmt.Sprintf(`function FindProxyForURL(url, host) { return "SOCKS5 %s"; }`, socksAddr)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "socks http ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestConnectThroughSOCKS4PACProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "socks4 connect ok")
	}))
	defer upstream.Close()
	socksAddr := startTestSOCKS4(t)
	pacPath := filepath.Join(t.TempDir(), "socks4.pac")
	if err := os.WriteFile(pacPath, []byte(fmt.Sprintf(`function FindProxyForURL(url, host) { return "SOCKS4 %s"; }`, socksAddr)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "socks4 connect ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestHTTPThroughSOCKS4PACProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "socks4 http ok")
	}))
	defer upstream.Close()
	socksAddr := startTestSOCKS4(t)
	pacPath := filepath.Join(t.TempDir(), "socks4-http.pac")
	if err := os.WriteFile(pacPath, []byte(fmt.Sprintf(`function FindProxyForURL(url, host) { return "SOCKS4 %s"; }`, socksAddr)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "socks4 http ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestHTTPPACProxyFallbackToDirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fallback http ok")
	}))
	defer upstream.Close()
	pacPath := filepath.Join(t.TempDir(), "fallback-http.pac")
	if err := os.WriteFile(pacPath, []byte(`function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:1; DIRECT"; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "fallback http ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestConnectPACProxyFallbackToDirect(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fallback connect ok")
	}))
	defer upstream.Close()
	pacPath := filepath.Join(t.TempDir(), "fallback-connect.pac")
	if err := os.WriteFile(pacPath, []byte(`function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:1; DIRECT"; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "fallback connect ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestConnectIdleTimeoutClosesTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			<-done
		}
	}()
	cfg := config.Default()
	cfg.Idle = 1
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer close(done)
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String(), ln.Addr().String())
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%s", resp.Status)
	}
	time.Sleep(1500 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = reader.Peek(1)
	if err == nil {
		t.Fatal("expected idle tunnel to close")
	}
}

func TestListenMultipleInterfaces(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "multi-listen ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Listen = "127.0.0.1, 127.0.0.2,127.0.0.1"
	px := startTestProxy(t, cfg)
	for _, host := range []string{"127.0.0.1", "127.0.0.2"} {
		proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, px.Port()))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatalf("%s did not accept connection: %v", host, err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(data) != "multi-listen ok" {
			t.Fatalf("%s status=%s body=%q", host, resp.Status, data)
		}
	}
}

func TestUpstreamProxyChain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "through chain")
	}))
	defer upstream.Close()
	parent := startTestProxy(t, config.Default())
	cfg := config.Default()
	cfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
	child := startTestProxy(t, cfg)
	client := proxyClient(t, child.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "through chain" {
		t.Fatalf("body=%q", data)
	}
}

func TestClientBasicAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "auth ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "BASIC"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %s", resp.Status)
	}
	_ = resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.SetBasicAuth("test", "12345")
	auth := req.Header.Get("Authorization")
	req.Header.Del("Authorization")
	req.Header.Set("Proxy-Authorization", auth)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "auth ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientBasicAuthSchemeCaseInsensitive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "case ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "BASIC"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", "basic "+base64.StdEncoding.EncodeToString([]byte("test:12345")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "case ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientAuthPersistsOnConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "conn auth ok")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "BASIC"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	auth := base64.StdEncoding.EncodeToString([]byte("test:12345"))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nConnection: keep-alive\r\n\r\n", upstream.URL, upstreamURL.Host, auth)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "conn auth ok" {
		t.Fatalf("first response status=%s body=%q", resp.Status, data)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.URL, upstreamURL.Host)
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "conn auth ok" {
		t.Fatalf("second response status=%s body=%q", resp.Status, data)
	}
}

func TestClientAuthZeroLengthBodyMethodRequiresHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "BASIC"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	auth := base64.StdEncoding.EncodeToString([]byte("test:12345"))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nConnection: keep-alive\r\n\r\n", upstream.URL, upstreamURL.Host, auth)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_, _ = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", upstream.URL, upstreamURL.Host)
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %s", resp.Status)
	}
}

func TestProxyHeadersStrippedBeforeUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Fatalf("Proxy-Authorization leaked upstream: %q", got)
		}
		if got := r.Header.Get("Proxy-Connection"); got != "" {
			t.Fatalf("Proxy-Connection leaked upstream: %q", got)
		}
		if got := r.Header.Get("Proxy-Custom"); got != "" {
			t.Fatalf("Proxy-Custom leaked upstream: %q", got)
		}
		fmt.Fprint(w, "headers ok")
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Proxy-Custom", "secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "headers ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientDigestAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "digest ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "DIGEST"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %s", resp.Status)
	}
	challenge := resp.Header.Get("Proxy-Authenticate")
	_ = resp.Body.Close()
	if !strings.Contains(challenge, "Digest") {
		t.Fatalf("missing digest challenge: %q", challenge)
	}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", digestAuthHeader(upstream.URL, digestNonceFromChallenge(t, challenge)))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "digest ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientDigestAuthSchemeCaseInsensitive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "digest case ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "DIGEST"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	challenge := resp.Header.Get("Proxy-Authenticate")
	_ = resp.Body.Close()
	auth := digestAuthHeader(upstream.URL, digestNonceFromChallenge(t, challenge))
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", strings.Replace(auth, "Digest ", "digest ", 1))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "digest case ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientDigestRejectsBadNonce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "DIGEST"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", digestAuthHeader(upstream.URL, "bad-nonce"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %s", resp.Status)
	}
}

func TestClientAnyAuthChallengesAndAcceptsBasic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "any ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "ANY"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	challenges := strings.Join(resp.Header.Values("Proxy-Authenticate"), ",")
	_ = resp.Body.Close()
	for _, want := range []string{"Negotiate", "NTLM", "Digest", "Basic"} {
		if !strings.Contains(challenges, want) {
			t.Fatalf("challenge missing %s: %q", want, challenges)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.SetBasicAuth("test", "12345")
	auth := req.Header.Get("Authorization")
	req.Header.Del("Authorization")
	req.Header.Set("Proxy-Authorization", auth)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "any ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientNTLMAuthValidatesConfiguredCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ntlm client ok")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "NTLM"
	cfg.ClientUsername = "DOMAIN\\test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: keep-alive\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type1))
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || ntlmMessageType(t, challengeHeader) != 2 {
		t.Fatalf("expected NTLM challenge, status=%s header=%q", resp.Status, challengeHeader)
	}
	_, challengeToken, _ := strings.Cut(challengeHeader, " ")
	challenge, err := base64.StdEncoding.DecodeString(challengeToken)
	if err != nil {
		t.Fatal(err)
	}
	type3, err := ntlmssp.NewAuthenticateMessage(challenge, "DOMAIN\\test", "12345", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type3))
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "ntlm client ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientNTLMRejectsWrongPassword(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "NTLM"
	cfg.ClientUsername = "DOMAIN\\test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: keep-alive\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type1))
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_, challengeToken, _ := strings.Cut(challengeHeader, " ")
	challenge, err := base64.StdEncoding.DecodeString(challengeToken)
	if err != nil {
		t.Fatal(err)
	}
	type3, err := ntlmssp.NewAuthenticateMessage(challenge, "DOMAIN\\test", "wrong", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type3))
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %s", resp.Status)
	}
}

func TestClientAnyAuthAcceptsNTLM(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "any ntlm ok")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "ANY"
	cfg.ClientUsername = "DOMAIN\\test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: keep-alive\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type1))
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	var challengeHeader string
	for _, value := range resp.Header.Values("Proxy-Authenticate") {
		if strings.HasPrefix(value, "NTLM ") {
			challengeHeader = value
			break
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if challengeHeader == "" || ntlmMessageType(t, challengeHeader) != 2 {
		t.Fatalf("missing NTLM challenge in %#v", resp.Header.Values("Proxy-Authenticate"))
	}
	_, challengeToken, _ := strings.Cut(challengeHeader, " ")
	challenge, err := base64.StdEncoding.DecodeString(challengeToken)
	if err != nil {
		t.Fatal(err)
	}
	type3, err := ntlmssp.NewAuthenticateMessage(challenge, "DOMAIN\\test", "12345", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type3))
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "any ntlm ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientNegotiateAcceptsRawNTLMSSP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "negotiate ntlm ok")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "NEGOTIATE"
	cfg.ClientUsername = "DOMAIN\\test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Negotiate %s\r\nConnection: keep-alive\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type1))
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || ntlmMessageType(t, challengeHeader) != 2 {
		t.Fatalf("expected Negotiate NTLM challenge, status=%s header=%q", resp.Status, challengeHeader)
	}
	_, challengeToken, _ := strings.Cut(challengeHeader, " ")
	challenge, err := base64.StdEncoding.DecodeString(challengeToken)
	if err != nil {
		t.Fatal(err)
	}
	type3, err := ntlmssp.NewAuthenticateMessage(challenge, "DOMAIN\\test", "12345", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Negotiate %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(type3))
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "negotiate ntlm ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientNegotiateAcceptsSPNEGOWrappedNTLMSSP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "spnego ntlm ok")
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg := config.Default()
	cfg.ClientAuth = "NEGOTIATE"
	cfg.ClientUsername = "DOMAIN\\test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	type1, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Negotiate %s\r\nConnection: keep-alive\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(spnegoNegTokenInit(type1)))
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_, challengeToken, _ := strings.Cut(challengeHeader, " ")
	wrappedChallenge, err := base64.StdEncoding.DecodeString(challengeToken)
	if err != nil {
		t.Fatal(err)
	}
	challenge, ok := unwrapSPNEGONTLMToken(wrappedChallenge)
	if resp.StatusCode != http.StatusProxyAuthRequired || !ok || binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		t.Fatalf("expected SPNEGO-wrapped NTLM challenge, status=%s header=%q", resp.Status, challengeHeader)
	}
	type3, err := ntlmssp.NewAuthenticateMessage(challenge, "DOMAIN\\test", "12345", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Negotiate %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstreamURL.Host, base64.StdEncoding.EncodeToString(spnegoNegTokenResp(type3)))
	resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "spnego ntlm ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientCommaAuthChallengesAndAcceptsDigest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "comma digest ok")
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.ClientAuth = "DIGEST,BASIC"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	challenges := strings.Join(resp.Header.Values("Proxy-Authenticate"), ",")
	challenge := resp.Header.Get("Proxy-Authenticate")
	_ = resp.Body.Close()
	for _, want := range []string{"Digest", "Basic"} {
		if !strings.Contains(challenges, want) {
			t.Fatalf("challenge missing %s: %q", want, challenges)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", digestAuthHeader(upstream.URL, digestNonceFromChallenge(t, challenge)))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if string(data) != "comma digest ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestClientAnySafeAuthOmitsBasic(t *testing.T) {
	cfg := config.Default()
	cfg.ClientAuth = "ANYSAFE"
	cfg.ClientUsername = "test"
	cfg.ClientPassword = "12345"
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	challenges := strings.Join(resp.Header.Values("Proxy-Authenticate"), ",")
	_ = resp.Body.Close()
	for _, want := range []string{"Negotiate", "NTLM", "Digest"} {
		if !strings.Contains(challenges, want) {
			t.Fatalf("challenge missing %s: %q", want, challenges)
		}
	}
	if strings.Contains(challenges, "Basic") {
		t.Fatalf("ANYSAFE should not offer Basic: %q", challenges)
	}
}

func TestUnsupportedClientAuthRejected(t *testing.T) {
	cfg := config.Default()
	cfg.ClientAuth = "BASIC,UNKNOWN"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected unsupported client auth error")
	}
}

func TestInvalidAllowRejected(t *testing.T) {
	cfg := config.Default()
	cfg.Allow = "example.com"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected invalid allow error")
	}
}

func TestUpstreamProxyBasicAuthHTTPAndConnect(t *testing.T) {
	httpUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "http parent auth ok")
	}))
	defer httpUp.Close()
	httpsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "connect parent auth ok")
	}))
	defer httpsUp.Close()
	parentCfg := config.Default()
	parentCfg.ClientAuth = "BASIC"
	parentCfg.ClientUsername = "test"
	parentCfg.ClientPassword = "12345"
	parent := startTestProxy(t, parentCfg)
	childCfg := config.Default()
	childCfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
	childCfg.Username = "test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	for _, tc := range []struct {
		url  string
		want string
	}{
		{httpUp.URL, "http parent auth ok"},
		{httpsUp.URL, "connect parent auth ok"},
	} {
		resp, err := client.Get(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(data) != tc.want {
			t.Fatalf("%s: status=%s body=%q", tc.url, resp.Status, data)
		}
	}
}

func TestUpstreamProxyDigestAuthHTTPAndConnect(t *testing.T) {
	httpUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "http parent digest ok")
	}))
	defer httpUp.Close()
	httpsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "connect parent digest ok")
	}))
	defer httpsUp.Close()
	parentCfg := config.Default()
	parentCfg.ClientAuth = "DIGEST"
	parentCfg.ClientUsername = "test"
	parentCfg.ClientPassword = "12345"
	parent := startTestProxy(t, parentCfg)
	for _, auth := range []struct {
		name string
		mode string
	}{
		{"explicit-digest", "DIGEST"},
		{"default-any", ""},
	} {
		t.Run(auth.name, func(t *testing.T) {
			childCfg := config.Default()
			childCfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
			childCfg.Auth = auth.mode
			childCfg.Username = "test"
			childCfg.Password = "12345"
			child := startTestProxy(t, childCfg)
			client := proxyClient(t, child.Port())
			for _, tc := range []struct {
				url  string
				want string
			}{
				{httpUp.URL, "http parent digest ok"},
				{httpsUp.URL, "connect parent digest ok"},
			} {
				resp, err := client.Get(tc.url)
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(data) != tc.want {
					t.Fatalf("%s: status=%s body=%q", tc.url, resp.Status, data)
				}
			}
		})
	}
}

func TestSelectProxyAuthenticateChallengePreservesDigestParams(t *testing.T) {
	challenge := `Digest realm="PxClient", nonce="abc", qop="auth", algorithm="MD5"`
	if got := selectProxyAuthenticateChallenge("ANY", []string{challenge, "Basic realm=\"PxClient\""}); got != challenge {
		t.Fatalf("got %q", got)
	}
	if got := selectProxyAuthenticateChallenge("BASIC", []string{challenge, "Basic realm=\"PxClient\""}); got != `Basic realm="PxClient"` {
		t.Fatalf("got %q", got)
	}
	if got := selectProxyAuthenticateChallenge("DIGEST", []string{challenge}); got != challenge {
		t.Fatalf("got %q", got)
	}
}

func TestUpstreamDigestAuthWithoutQop(t *testing.T) {
	cfg := config.Default()
	cfg.Auth = "DIGEST"
	cfg.Username = "test"
	cfg.Password = "12345"
	auth := UpstreamProxyAuthHeader(cfg, http.MethodGet, "http://example.test/resource", []string{`Digest realm="PxClient", nonce="abc"`})
	if !strings.HasPrefix(auth, "Digest ") {
		t.Fatalf("got %q", auth)
	}
	if strings.Contains(auth, "qop=") || strings.Contains(auth, "cnonce=") || strings.Contains(auth, "nc=") {
		t.Fatalf("legacy digest auth should omit qop fields: %q", auth)
	}
	params := parseAuthParams(strings.TrimPrefix(auth, "Digest "))
	ha1 := md5hex("test:PxClient:12345")
	ha2 := md5hex(http.MethodGet + ":http://example.test/resource")
	if params["response"] != md5hex(ha1+":abc:"+ha2) {
		t.Fatalf("bad response: %#v", params)
	}
}

func TestUpstreamDigestAuthSelectsAuthQop(t *testing.T) {
	cfg := config.Default()
	cfg.Auth = "DIGEST"
	cfg.Username = "test"
	cfg.Password = "12345"
	auth := UpstreamProxyAuthHeader(cfg, http.MethodGet, "http://example.test/resource", []string{`Digest realm="PxClient", nonce="abc", qop="auth,auth-int"`})
	params := parseAuthParams(strings.TrimPrefix(auth, "Digest "))
	if params["qop"] != "auth" {
		t.Fatalf("got %q in %q", params["qop"], auth)
	}
	ha1 := md5hex("test:PxClient:12345")
	ha2 := md5hex(http.MethodGet + ":http://example.test/resource")
	want := md5hex(ha1 + ":abc:00000001:pxgocnonce:auth:" + ha2)
	if params["response"] != want {
		t.Fatalf("bad response: %#v", params)
	}
}

func TestSelectProxyAuthenticateChallengeAuthSelectors(t *testing.T) {
	challenges := []string{
		`Basic realm="PxClient"`,
		`Digest realm="PxClient", nonce="abc", qop="auth", algorithm="MD5"`,
		`NTLM`,
	}
	tests := []struct {
		auth string
		want string
	}{
		{"ANYSAFE", "NTLM"},
		{"NONTLM", `Digest realm="PxClient", nonce="abc", qop="auth", algorithm="MD5"`},
		{"SAFENONTLM", `Digest realm="PxClient", nonce="abc", qop="auth", algorithm="MD5"`},
		{"ONLYBASIC", `Basic realm="PxClient"`},
		{"NONE", ""},
	}
	for _, tt := range tests {
		if got := selectProxyAuthenticateChallenge(tt.auth, challenges); got != tt.want {
			t.Fatalf("%s: got %q want %q", tt.auth, got, tt.want)
		}
	}
}

func TestUnsupportedUpstreamAuthRejected(t *testing.T) {
	cfg := config.Default()
	cfg.Auth = "UNKNOWN"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected unsupported upstream auth error")
	}
}

func TestKerberosRequiresUsername(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Kerberos manager is ignored on Windows")
	}
	cfg := config.Default()
	cfg.Kerberos = true
	if _, err := New(cfg); err == nil {
		t.Fatal("expected kerberos username error")
	}
}

func TestUpstreamNegotiateFailureForcesKerberosReloadHTTP(t *testing.T) {
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", "Negotiate")
		http.Error(w, "auth required", http.StatusProxyAuthRequired)
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = "NEGOTIATE"
	childCfg.Username = "user@REALM"
	childCfg.Password = "secret"
	child := startTestProxy(t, childCfg)
	var reloads int
	child.krb = testKerberosManager(&reloads)
	client := proxyClient(t, child.Port())
	resp, err := client.Get("http://kerberos.example.test/resource")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected upstream 407, got %s", resp.Status)
	}
	if reloads != 1 {
		t.Fatalf("forced kerberos reload count=%d, want 1", reloads)
	}
}

func TestUpstreamNegotiateFailureForcesKerberosReloadConnect(t *testing.T) {
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Fatalf("expected CONNECT, got %s", r.Method)
		}
		w.Header().Set("Proxy-Authenticate", "Negotiate")
		http.Error(w, "auth required", http.StatusProxyAuthRequired)
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = "NEGOTIATE"
	childCfg.Username = "user@REALM"
	childCfg.Password = "secret"
	child := startTestProxy(t, childCfg)
	var reloads int
	child.krb = testKerberosManager(&reloads)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", child.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "CONNECT kerberos.example.test:443 HTTP/1.1\r\nHost: kerberos.example.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected local 502 for failed upstream CONNECT, got %s", resp.Status)
	}
	if reloads != 1 {
		t.Fatalf("forced kerberos reload count=%d, want 1", reloads)
	}
}

func TestUnsupportedUpstreamNTLMDoesNotFallBackToBasic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()
	parentCfg := config.Default()
	parentCfg.ClientAuth = "BASIC"
	parentCfg.ClientUsername = "test"
	parentCfg.ClientPassword = "12345"
	parent := startTestProxy(t, parentCfg)
	childCfg := config.Default()
	childCfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
	childCfg.Auth = "NTLM"
	childCfg.Username = "test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected upstream 407, got %s", resp.Status)
	}
}

func TestUpstreamProxyNTLMAuthHTTP(t *testing.T) {
	runUpstreamConnectionAuthHTTP(t, "NTLM", "ntlm http ok")
}

func TestUpstreamProxyNegotiateAuthHTTP(t *testing.T) {
	runUpstreamConnectionAuthHTTP(t, "Negotiate", "negotiate http ok")
}

func TestUpstreamProxyNegotiateAuthHTTPWithSPNEGO(t *testing.T) {
	runUpstreamSPNEGOAuthHTTP(t)
}

func TestUpstreamProxyNTLMAuthConnect(t *testing.T) {
	runUpstreamConnectionAuthConnect(t, "NTLM")
}

func TestUpstreamProxyNegotiateAuthConnect(t *testing.T) {
	runUpstreamConnectionAuthConnect(t, "Negotiate")
}

func TestUpstreamProxyNegotiateAuthConnectWithSPNEGO(t *testing.T) {
	runUpstreamSPNEGOAuthConnect(t)
}

func runUpstreamConnectionAuthHTTP(t *testing.T, scheme, body string) {
	t.Helper()
	var authHeaders []string
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		authHeaders = append(authHeaders, auth)
		switch len(authHeaders) {
		case 1:
			w.Header().Set("Proxy-Authenticate", scheme)
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
		case 2:
			if !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(scheme)+" ") || ntlmMessageType(t, auth) != 1 {
				t.Fatalf("expected %s type 1, got %q", scheme, auth)
			}
			w.Header().Set("Proxy-Authenticate", scheme+" "+minimalNTLMChallenge(t))
			http.Error(w, "challenge", http.StatusProxyAuthRequired)
		case 3:
			if !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(scheme)+" ") || ntlmMessageType(t, auth) != 3 {
				t.Fatalf("expected %s type 3, got %q", scheme, auth)
			}
			fmt.Fprint(w, body)
		default:
			t.Fatalf("unexpected extra request with auth %q", auth)
		}
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = strings.ToUpper(scheme)
	childCfg.Username = "DOMAIN\\test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	resp, err := client.Get("http://ntlm.example.test/resource")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != body {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func runUpstreamSPNEGOAuthHTTP(t *testing.T) {
	t.Helper()
	var authHeaders []string
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		authHeaders = append(authHeaders, auth)
		switch len(authHeaders) {
		case 1:
			w.Header().Set("Proxy-Authenticate", "Negotiate")
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
		case 2:
			if ntlmMessageType(t, auth) != 1 || !authTokenIsSPNEGO(t, auth) {
				t.Fatalf("expected SPNEGO NTLM type 1, got %q", auth)
			}
			w.Header().Set("Proxy-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(spnegoNegTokenResp(minimalNTLMChallengeBytes())))
			http.Error(w, "challenge", http.StatusProxyAuthRequired)
		case 3:
			if ntlmMessageType(t, auth) != 3 || !authTokenIsSPNEGO(t, auth) {
				t.Fatalf("expected SPNEGO NTLM type 3, got %q", auth)
			}
			fmt.Fprint(w, "spnego upstream http ok")
		default:
			t.Fatalf("unexpected extra request with auth %q", auth)
		}
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = "NEGOTIATE"
	childCfg.Username = "DOMAIN\\test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	resp, err := client.Get("http://spnego.example.test/resource")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "spnego upstream http ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func runUpstreamConnectionAuthConnect(t *testing.T, scheme string) {
	t.Helper()
	var authHeaders []string
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Fatalf("expected CONNECT, got %s", r.Method)
		}
		auth := r.Header.Get("Proxy-Authorization")
		authHeaders = append(authHeaders, auth)
		switch len(authHeaders) {
		case 1:
			w.Header().Set("Proxy-Authenticate", scheme)
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
		case 2:
			if ntlmMessageType(t, auth) != 1 {
				t.Fatalf("expected %s type 1, got %q", scheme, auth)
			}
			w.Header().Set("Proxy-Authenticate", scheme+" "+minimalNTLMChallenge(t))
			http.Error(w, "challenge", http.StatusProxyAuthRequired)
		case 3:
			if ntlmMessageType(t, auth) != 3 {
				t.Fatalf("expected %s type 3, got %q", scheme, auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected extra request with auth %q", auth)
		}
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = strings.ToUpper(scheme)
	childCfg.Username = "DOMAIN\\test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", child.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "CONNECT ntlm.example.test:443 HTTP/1.1\r\nHost: ntlm.example.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%s", resp.Status)
	}
}

func runUpstreamSPNEGOAuthConnect(t *testing.T) {
	t.Helper()
	var authHeaders []string
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Fatalf("expected CONNECT, got %s", r.Method)
		}
		auth := r.Header.Get("Proxy-Authorization")
		authHeaders = append(authHeaders, auth)
		switch len(authHeaders) {
		case 1:
			w.Header().Set("Proxy-Authenticate", "Negotiate")
			http.Error(w, "auth required", http.StatusProxyAuthRequired)
		case 2:
			if ntlmMessageType(t, auth) != 1 || !authTokenIsSPNEGO(t, auth) {
				t.Fatalf("expected SPNEGO NTLM type 1, got %q", auth)
			}
			w.Header().Set("Proxy-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(spnegoNegTokenResp(minimalNTLMChallengeBytes())))
			http.Error(w, "challenge", http.StatusProxyAuthRequired)
		case 3:
			if ntlmMessageType(t, auth) != 3 || !authTokenIsSPNEGO(t, auth) {
				t.Fatalf("expected SPNEGO NTLM type 3, got %q", auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected extra request with auth %q", auth)
		}
	}))
	defer parent.Close()
	parentURL, _ := url.Parse(parent.URL)
	childCfg := config.Default()
	childCfg.Server = parentURL.Host
	childCfg.Auth = "NEGOTIATE"
	childCfg.Username = "DOMAIN\\test"
	childCfg.Password = "12345"
	child := startTestProxy(t, childCfg)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", child.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "CONNECT spnego.example.test:443 HTTP/1.1\r\nHost: spnego.example.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%s", resp.Status)
	}
}

func TestAuthNonePassesClientProxyAuthorizationUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "auth none pass-through ok")
	}))
	defer upstream.Close()
	parentCfg := config.Default()
	parentCfg.ClientAuth = "BASIC"
	parentCfg.ClientUsername = "test"
	parentCfg.ClientPassword = "12345"
	parent := startTestProxy(t, parentCfg)
	childCfg := config.Default()
	childCfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
	childCfg.Auth = "NONE"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected parent 407 without pass-through credentials, got %s", resp.Status)
	}
	_ = resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.SetBasicAuth("test", "12345")
	auth := req.Header.Get("Authorization")
	req.Header.Del("Authorization")
	req.Header.Set("Proxy-Authorization", auth)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "auth none pass-through ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestAuthNonePassesZeroLengthBodyAuthUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.ContentLength != 0 {
			t.Fatalf("unexpected request method=%s contentLength=%d", r.Method, r.ContentLength)
		}
		fmt.Fprint(w, "zero body auth none ok")
	}))
	defer upstream.Close()
	parentCfg := config.Default()
	parentCfg.ClientAuth = "BASIC"
	parentCfg.ClientUsername = "test"
	parentCfg.ClientPassword = "12345"
	parent := startTestProxy(t, parentCfg)
	childCfg := config.Default()
	childCfg.Server = fmt.Sprintf("127.0.0.1:%d", parent.Port())
	childCfg.Auth = "NONE"
	child := startTestProxy(t, childCfg)
	client := proxyClient(t, child.Port())
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/upload", http.NoBody)
	req.ContentLength = 0
	req.SetBasicAuth("test", "12345")
	auth := req.Header.Get("Authorization")
	req.Header.Del("Authorization")
	req.Header.Set("Proxy-Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "zero body auth none ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestProxyReloadDoesNotRefreshLocalPACFile(t *testing.T) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"} {
		t.Setenv(key, "")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pac reload ok")
	}))
	defer upstream.Close()
	pacPath := filepath.Join(t.TempDir(), "proxy.pac")
	if err := os.WriteFile(pacPath, []byte(`function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:1"; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.PAC = pacPath
	cfg.ProxyReload = 1
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected bad gateway through stale PAC proxy, got %s", resp.Status)
	}
	if err := os.WriteFile(pacPath, []byte(`function FindProxyForURL(url, host) { return "DIRECT"; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	resp, err = client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("local PAC should not reload, got %s", resp.Status)
	}
}

func TestProxyReloadRefreshesHTTPPACURL(t *testing.T) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"} {
		t.Setenv(key, "")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pac url reload ok")
	}))
	defer upstream.Close()
	var pacBody atomic.Value
	pacBody.Store(`function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:1"; }`)
	pacSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pacBody.Load().(string))
	}))
	defer pacSrv.Close()
	cfg := config.Default()
	cfg.PAC = pacSrv.URL
	cfg.ProxyReload = 1
	px := startTestProxy(t, cfg)
	client := proxyClient(t, px.Port())
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected bad gateway through stale PAC URL proxy, got %s", resp.Status)
	}
	pacBody.Store(`function FindProxyForURL(url, host) { return "DIRECT"; }`)
	time.Sleep(1100 * time.Millisecond)
	resp, err = client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "pac url reload ok" {
		t.Fatalf("status=%s body=%q", resp.Status, data)
	}
}

func TestAllowRestrictsClientAddress(t *testing.T) {
	cfg := config.Default()
	cfg.Allow = "127.0.*.*"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isClientAllowed("127.0.0.1:12345") {
		t.Fatal("127.0.0.1 should be allowed")
	}
	if s.isClientAllowed("10.0.0.2:12345") {
		t.Fatal("10.0.0.2 should be denied")
	}
}

func TestHostonlyRestrictsToLocalInterfaceAddresses(t *testing.T) {
	cfg := config.Default()
	cfg.Hostonly = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isClientAllowed("127.0.0.1:12345") {
		t.Fatal("localhost should be allowed in hostonly mode")
	}
	if s.isClientAllowed("203.0.113.10:12345") {
		t.Fatal("non-local test address should be denied in hostonly mode")
	}
}

func TestGatewayHostonlyAllowsCustomAllowRules(t *testing.T) {
	cfg := config.Default()
	cfg.Gateway = true
	cfg.Hostonly = true
	cfg.Allow = "10.0.*.*"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isClientAllowed("10.0.2.3:12345") {
		t.Fatal("gateway hostonly should honor explicit allow rules")
	}
	if s.isClientAllowed("203.0.113.10:12345") {
		t.Fatal("address outside explicit allow and host interfaces should be denied")
	}
}

func TestQuitEndpointRequiresAllowedClient(t *testing.T) {
	cfg := config.Default()
	cfg.Allow = "10.0.*.*"
	px := startTestProxy(t, cfg)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/PxgoQuit", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%s, want 403", resp.Status)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("proxy stopped after forbidden quit: %v", err)
	}
	_ = conn.Close()
}

func TestQuitEndpointStopsProxy(t *testing.T) {
	px := startTestProxy(t, config.Default())
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/PxgoQuit", px.Port()))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%s", resp.Status)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", px.Port()), 50*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("proxy still accepts connections")
}

func TestKerberosPasswordFuncRefetchesKeyring(t *testing.T) {
	t.Setenv("PXGO_KEYRING_PLAINTEXT", "1")
	t.Setenv("PXGO_KEYRING_FILE", filepath.Join(t.TempDir(), "keyring.json"))
	cfg := config.Default()
	cfg.Kerberos = true
	cfg.Username = "user@REALM"
	cfg.Password = "startup"
	if err := config.StorePassword(config.Realm, cfg.Username, "first"); err != nil {
		t.Fatal(err)
	}
	mgr, err := buildKerberosManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Cleanup)
	if got := mgr.PasswordFunc(); got == nil || *got != "first" {
		t.Fatalf("password=%v, want first", got)
	}
	if err := config.StorePassword(config.Realm, cfg.Username, "second"); err != nil {
		t.Fatal(err)
	}
	if got := mgr.PasswordFunc(); got == nil || *got != "second" {
		t.Fatalf("password=%v, want second", got)
	}
}

func TestProxyReloadableModes(t *testing.T) {
	tests := []struct {
		name string
		mode int
		pac  string
		want bool
	}{
		{"config", wproxy.ModeConfig, "", false},
		{"env", wproxy.ModeEnv, "", false},
		{"local config pac", wproxy.ModeConfigPAC, "/tmp/proxy.pac", false},
		{"http config pac", wproxy.ModeConfigPAC, "http://proxy/pac.js", true},
		{"system manual", wproxy.ModeManual, "", true},
		{"system pac", wproxy.ModePAC, "", true},
		{"system auto", wproxy.ModeAuto, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: config.Config{PAC: tc.pac}, w: &wproxy.Wproxy{Mode: tc.mode}}
			if got := s.proxyReloadableLocked(); got != tc.want {
				t.Fatalf("reloadable=%v want %v", got, tc.want)
			}
		})
	}
}

func TestReplayableBodySpillsLargeBodiesToTempFile(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), maxMemoryBody+4096)
	body, err := newReplayableBody(io.NopCloser(bytes.NewReader(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if body.path == "" {
		t.Fatal("large body should spill to a temp file")
	}
	if body.Size() != int64(len(payload)) {
		t.Fatalf("size=%d want %d", body.Size(), len(payload))
	}
	for i := 0; i < 2; i++ {
		rc, err := body.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatal("replayed body mismatch")
		}
	}
	path := body.path
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp body file still exists: %v", err)
	}
}

func digestAuthHeader(uri, nonce string) string {
	username := "test"
	password := "12345"
	method := http.MethodGet
	realm := "PxClient"
	nc := "00000001"
	cnonce := "abcdef"
	qop := "auth"
	ha1 := testMD5(username + ":" + realm + ":" + password)
	ha2 := testMD5(method + ":" + uri)
	response := testMD5(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		username, realm, nonce, uri, qop, nc, cnonce, response)
}

func digestNonceFromChallenge(t *testing.T, challenge string) string {
	t.Helper()
	params := parseAuthParams(strings.TrimPrefix(challenge, "Digest "))
	nonce := params["nonce"]
	if nonce == "" {
		t.Fatalf("missing nonce in challenge %q", challenge)
	}
	return nonce
}

func testMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func minimalNTLMChallenge(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(minimalNTLMChallengeBytes())
}

func minimalNTLMChallengeBytes() []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("NTLMSSP\x00")
	_ = binary.Write(buf, binary.LittleEndian, uint32(2))
	buf.Write(make([]byte, 8))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xa0888201))
	buf.Write([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	buf.Write(make([]byte, 16))
	return buf.Bytes()
}

func ntlmMessageType(t *testing.T, header string) uint32 {
	t.Helper()
	raw := authTokenBytes(t, header)
	if !isNTLMSSP(raw) {
		var ok bool
		raw, ok = unwrapSPNEGONTLMToken(raw)
		if !ok {
			t.Fatalf("bad NTLM/SPNEGO message %x", raw)
		}
	}
	return binary.LittleEndian.Uint32(raw[8:12])
}

func authTokenIsSPNEGO(t *testing.T, header string) bool {
	t.Helper()
	raw := authTokenBytes(t, header)
	if isNTLMSSP(raw) {
		return false
	}
	_, ok := unwrapSPNEGONTLMToken(raw)
	return ok
}

func authTokenBytes(t *testing.T, header string) []byte {
	t.Helper()
	_, token, ok := strings.Cut(header, " ")
	if !ok {
		t.Fatalf("missing NTLM token in %q", header)
	}
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testKerberosManager(reloads *int) *kerberos.Manager {
	password := "secret"
	mgr := kerberos.New("user@REALM", func() *string { return &password }, false)
	mgr.NextCheck = time.Now().Add(time.Hour)
	mgr.KinitWithPasswordFunc = func() bool {
		*reloads++
		return true
	}
	mgr.KinitRenewFunc = func() bool {
		*reloads++
		return true
	}
	mgr.KlistValidFunc = func() bool {
		return true
	}
	return mgr
}

func TestLargeHTTPAndHTTPS(t *testing.T) {
	payload := bytes.Repeat([]byte("PxLargeDataTest"), 160000)
	want := sha256.Sum256(payload)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("X-SHA256", hex.EncodeToString(want[:]))
			_, _ = w.Write(payload)
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			got := sha256.Sum256(body)
			fmt.Fprintf(w, `{"received":%d,"sha256":"%s"}`, len(body), hex.EncodeToString(got[:]))
		}
	})
	httpUp := httptest.NewServer(handler)
	defer httpUp.Close()
	httpsUp := httptest.NewTLSServer(handler)
	defer httpsUp.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, target := range []string{httpUp.URL, httpsUp.URL} {
		t.Run(target, func(t *testing.T) {
			resp, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if got := sha256.Sum256(data); got != want {
				t.Fatalf("GET hash mismatch")
			}
			resp, err = client.Post(target, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			data, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !strings.Contains(string(data), fmt.Sprintf(`"received":%d`, len(payload))) || !strings.Contains(string(data), hex.EncodeToString(want[:])) {
				t.Fatalf("bad POST response %q", data)
			}
		})
	}
}

func TestLargeDataMultipleSizes(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			size := 2 * 1024 * 1024
			switch {
			case strings.Contains(r.URL.Path, "20mb"):
				size = 20 * 1024 * 1024
			case strings.Contains(r.URL.Path, "10mb"):
				size = 10 * 1024 * 1024
			case strings.Contains(r.URL.Path, "5mb"):
				size = 5 * 1024 * 1024
			}
			body := makeLargePayload(size)
			sum := sha256.Sum256(body)
			w.Header().Set("X-SHA256", hex.EncodeToString(sum[:]))
			_, _ = w.Write(body)
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			fmt.Fprintf(w, `{"received":%d,"sha256":"%s"}`, len(body), hex.EncodeToString(sum[:]))
		}
	})
	httpUp := httptest.NewServer(handler)
	defer httpUp.Close()
	httpsUp := httptest.NewTLSServer(handler)
	defer httpsUp.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, tc := range []struct {
		name string
		size int
		path string
	}{
		{"2mb", 2 * 1024 * 1024, "/large/2mb"},
		{"5mb", 5 * 1024 * 1024, "/large/5mb"},
		{"10mb", 10 * 1024 * 1024, "/large/10mb"},
		{"20mb", 20 * 1024 * 1024, "/large/20mb"},
	} {
		for _, baseURL := range []string{httpUp.URL, httpsUp.URL} {
			t.Run(tc.name+"-"+baseURL[:4], func(t *testing.T) {
				expected := makeLargePayload(tc.size)
				expectedSum := sha256.Sum256(expected)
				resp, err := client.Get(baseURL + tc.path)
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if len(data) != tc.size {
					t.Fatalf("GET size=%d want %d", len(data), tc.size)
				}
				if got := sha256.Sum256(data); got != expectedSum {
					t.Fatalf("GET hash mismatch")
				}
				resp, err = client.Post(baseURL+"/upload", "application/octet-stream", bytes.NewReader(expected))
				if err != nil {
					t.Fatal(err)
				}
				data, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if !strings.Contains(string(data), fmt.Sprintf(`"received":%d`, tc.size)) || !strings.Contains(string(data), hex.EncodeToString(expectedSum[:])) {
					t.Fatalf("bad POST response %q", data)
				}
			})
		}
	}
}

func TestMixedConcurrentLargeTransfers(t *testing.T) {
	size := 5 * 1024 * 1024
	payload := makeLargePayload(size)
	expected := sha256.Sum256(payload)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			fmt.Fprintf(w, `{"received":%d,"sha256":"%s"}`, len(body), hex.EncodeToString(sum[:]))
			return
		}
		_, _ = w.Write(payload)
	})
	httpUp := httptest.NewServer(handler)
	defer httpUp.Close()
	httpsUp := httptest.NewTLSServer(handler)
	defer httpsUp.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, baseURL := range []string{httpUp.URL, httpsUp.URL} {
		t.Run(baseURL[:4], func(t *testing.T) {
			var wg sync.WaitGroup
			errs := make(chan error, 6)
			for i := 0; i < 3; i++ {
				wg.Add(2)
				go func() {
					defer wg.Done()
					resp, err := client.Get(baseURL + "/large")
					if err != nil {
						errs <- err
						return
					}
					data, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if len(data) != size {
						errs <- fmt.Errorf("GET size=%d want %d", len(data), size)
						return
					}
					if got := sha256.Sum256(data); got != expected {
						errs <- errors.New("GET hash mismatch")
					}
				}()
				go func() {
					defer wg.Done()
					resp, err := client.Post(baseURL+"/upload", "application/octet-stream", bytes.NewReader(payload))
					if err != nil {
						errs <- err
						return
					}
					data, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if !strings.Contains(string(data), fmt.Sprintf(`"received":%d`, size)) || !strings.Contains(string(data), hex.EncodeToString(expected[:])) {
						errs <- fmt.Errorf("bad POST response %q", data)
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func makeLargePayload(size int) []byte {
	block := []byte("PxLargeDataTest")
	out := make([]byte, size)
	for i := range out {
		out[i] = block[i%len(block)]
	}
	return out
}

func TestConcurrentRequests(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(upstream.URL)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- errors.New(resp.Status)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPThroughputConcurrencyLevels(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"ok","data":"xxxxxxxxxxxxxxxxxxxxxxxx"}`)
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, conc := range []int{1, 10, 50, 100} {
		t.Run(fmt.Sprintf("concurrency-%d", conc), func(t *testing.T) {
			before := runtime.NumGoroutine()
			results := runConcurrentProxyRequests(conc, 100, func() error {
				resp, err := client.Get(upstream.URL)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode < 200 || resp.StatusCode >= 400 {
					return errors.New(resp.Status)
				}
				return nil
			})
			successes := countNil(results)
			if successes < 80 {
				t.Fatalf("too many HTTP failures at concurrency %d: %d/%d succeeded", conc, successes, len(results))
			}
			t.Logf("HTTP concurrency %d: %d/%d succeeded, goroutines before=%d after=%d", conc, successes, len(results), before, runtime.NumGoroutine())
		})
	}
}

func TestCONNECTThroughputConcurrencyLevels(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"ok","data":"xxxxxxxxxxxxxxxxxxxxxxxx"}`)
	}))
	defer upstream.Close()
	px := startTestProxy(t, config.Default())
	client := proxyClient(t, px.Port())
	for _, conc := range []int{1, 10, 50, 100} {
		t.Run(fmt.Sprintf("concurrency-%d", conc), func(t *testing.T) {
			before := runtime.NumGoroutine()
			results := runConcurrentProxyRequests(conc, 100, func() error {
				resp, err := client.Get(upstream.URL)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode < 200 || resp.StatusCode >= 400 {
					return errors.New(resp.Status)
				}
				return nil
			})
			successes := countNil(results)
			if successes < 80 {
				t.Fatalf("too many CONNECT failures at concurrency %d: %d/%d succeeded", conc, successes, len(results))
			}
			t.Logf("CONNECT concurrency %d: %d/%d succeeded, goroutines before=%d after=%d", conc, successes, len(results), before, runtime.NumGoroutine())
		})
	}
}

func startTestSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSOCKS5Conn(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func handleTestSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		lenb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenb); err != nil {
			return
		}
		name := make([]byte, int(lenb[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	portb := make([]byte, 2)
	if _, err := io.ReadFull(conn, portb); err != nil {
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portb))))
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	relay(conn, target, 5*time.Second)
}

func startTestSOCKS4(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestSOCKS4Conn(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func handleTestSOCKS4Conn(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x04 || header[1] != 0x01 {
		return
	}
	for {
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		if b[0] == 0x00 {
			break
		}
	}
	host := net.IP(header[4:8]).String()
	if header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0 {
		var name []byte
		for {
			b := make([]byte, 1)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			if b[0] == 0x00 {
				break
			}
			name = append(name, b[0])
		}
		host = string(name)
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(header[2:4]))))
	if err != nil {
		_, _ = conn.Write([]byte{0x00, 0x5b, 0, 0, 127, 0, 0, 1})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{0x00, 0x5a, 0, 0, 127, 0, 0, 1}); err != nil {
		return
	}
	relay(conn, target, 5*time.Second)
}

func runConcurrentProxyRequests(concurrency, total int, fn func() error) []error {
	results := make([]error, total)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = fn()
		}(i)
	}
	wg.Wait()
	return results
}

func countNil(results []error) int {
	count := 0
	for _, err := range results {
		if err == nil {
			count++
		}
	}
	return count
}
