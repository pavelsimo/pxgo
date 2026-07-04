package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/debug"
	"github.com/pavelsimo/pxgo/internal/proxy"
	"github.com/pavelsimo/pxgo/internal/winstartup"
	"golang.org/x/term"
)

var version = "dev"

const (
	authNone    = "NONE"
	localhostIP = "127.0.0.1"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			debug.LogPanic(config.GetLogfile(config.LogCWD), recovered)
			exitCode = 1
		}
	}()
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cfg.Help {
		printHelp()
		return 0
	}
	if cfg.Version {
		fmt.Println(version)
		return 0
	}
	if cfg.Save {
		path := config.ConfigPathForSave(cfg.ConfigPath)
		if err := config.SaveINI(path, cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Fprintf(os.Stdout, "Configuration saved to %s\n", path)
		if data, err := os.ReadFile(path); err == nil {
			fmt.Fprint(os.Stdout, string(data))
		}
		return 0
	}
	if cfg.Install {
		cmd, err := winstartup.BuildRunCommand(os.Args[0], config.ConfigPathForSave(cfg.ConfigPath), func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 6
		}
		if err := installStartup(cmd, cfg.Force); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 6
		}
		return 0
	}
	if cfg.Uninstall {
		if err := uninstallStartup(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 6
		}
		return 0
	}
	if cfg.PasswordAction {
		if cfg.Password == "" {
			fmt.Fprintf(os.Stderr, "Password for %s: ", cfg.Username)
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			cfg.Password = string(raw)
		}
		if err := config.StorePassword(config.Realm, cfg.Username, cfg.Password); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Fprintf(os.Stdout, "Password saved for %s\n", cfg.Username)
		return 0
	}
	if cfg.ClientPasswordAction {
		if cfg.ClientPassword == "" {
			fmt.Fprintf(os.Stderr, "Password for %s: ", cfg.ClientUsername)
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			cfg.ClientPassword = string(raw)
		}
		if err := config.StorePassword(config.ClientRealm, cfg.ClientUsername, cfg.ClientPassword); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Fprintf(os.Stdout, "Password saved for %s\n", cfg.ClientUsername)
		return 0
	}
	if cfg.Quit {
		if err := quit(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		return 0
	}
	if cfg.Restart {
		if err := quit(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := setupDebug(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cfg.Test != "" {
		if err := runSelfTest(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 4
		}
		return 0
	}
	s, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- s.Start() }()
	select {
	case err := <-errc:
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 5
		}
	case <-ctx.Done():
		debug.Dprint("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdownCtx)
	}
	if d := debug.Instance(); d != nil {
		_ = d.Close()
	}
	return 0
}

func setupDebug(cfg config.Config) error {
	switch cfg.Log {
	case config.LogNone:
		return nil
	case config.LogStdout:
		_, err := debug.New("", false)
		return err
	default:
		path := config.GetLogfile(cfg.Log)
		if path == "" {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		_, err := debug.New(path, false)
		return err
	}
}

func printHelp() {
	fmt.Println(`pxgo - HTTP/HTTPS proxy

Usage:
  pxgo [options]

Options:
  --proxy, --server=HOST[:PORT]   Upstream proxy server
  --pac=PATH_OR_URL               PAC file path or URL
  --pac-encoding=ENCODING         PAC file encoding
  --port=PORT                     Listen port
  --listen=IP                     Listen address
  --gateway                       Listen on all interfaces
  --hostonly                      Allow local host interfaces only
  --allow=IPGLOB                  Client allow list
  --noproxy=LIST                  Direct-connect bypass list
  --useragent=VALUE               Override forwarded User-Agent
  --auth=TYPE                     Upstream auth: ANY, ANYSAFE, NEGOTIATE, NTLM, DIGEST, BASIC, NONE
  --username=USER                 Upstream auth username
  --kerberos                      Enable Kerberos ticket management
  --client-auth=TYPE              Client auth: NONE, ANY, ANYSAFE, NEGOTIATE, NTLM, DIGEST, BASIC
  --client-username=USER          Downstream auth username
  --client-nosspi=0|1             Disable SSPI for downstream auth compatibility
  --config=PATH                   Read or save pxgo.ini at PATH
  --save                          Save configuration to pxgo.ini
  --password                      Store upstream password
  --client-password               Store downstream password
  --log= | PXGO_LOG= | settings:log=
  Enable debug logging. default: 0
    1 = Log to script dir [--debug]
    2 = Log to working dir
    3 = Log to working dir with unique filename [--uniqlog]
    4 = Log to stdout [--verbose]. Implies --foreground
  --quit                          Stop a running proxy
  --restart                       Quit then start the proxy
  --install                       Install pxgo in Windows startup registry
  --uninstall                     Remove pxgo from Windows startup registry
  --force                         Overwrite existing Windows startup entry
  --test[=URL|all[:BASE]]         Run self-test through the proxy
  --test-auth                     Self-test using configured upstream auth via auth=NONE
  --version                       Print version
  -h, --help                      Show help`)
}

func quit(cfg config.Config) error {
	addr := net.JoinHostPort(listenForClient(cfg.Listen), fmt.Sprint(cfg.Port))
	if err := waitForRunningProxy(addr); err != nil {
		return err
	}
	client := http.Client{Timeout: 2 * time.Second}
	url := "http://" + addr + "/PxgoQuit"
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("quit failed: cannot quit pxgo on remote or disallowed host")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("quit failed: %s", resp.Status)
		}
		if waitForClosed(addr, 2*time.Second) {
			return nil
		}
		lastErr = fmt.Errorf("quit failed: proxy still running")
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("quit failed")
}

func waitForRunningProxy(addr string) error {
	for attempt := 0; attempt < 5; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if isConnectionRefused(err) {
			return fmt.Errorf("pxgo is not running")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("pxgo is not responding at %s", addr)
}

func waitForClosed(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return true
		}
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func runSelfTest(cfg config.Config) error {
	testAuthCfg := cfg
	if cfg.TestAuth {
		cfg.Auth = authNone
	}
	s, err := proxy.New(cfg)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Start() }()
	if err := waitPort(cfg.Listen, cfg.Port); err != nil {
		return err
	}
	defer func() { _ = s.Shutdown(context.Background()) }()

	urls := selfTestURLs(cfg.Test)
	allMode := selfTestAllMode(cfg.Test)
	if !allMode {
		urls = []string{cfg.Test}
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", listenForClient(cfg.Listen), cfg.Port))
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-test intentionally accepts arbitrary test endpoints.
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	methods := []string{http.MethodGet}
	if allMode {
		methods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(urls)*len(methods))
	for _, u := range urls {
		for _, method := range methods {
			wg.Add(1)
			go func(u, method string) {
				defer wg.Done()
				body := strings.NewReader("")
				if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
					body = strings.NewReader("px-go-test")
				}
				targetURL := u
				if allMode {
					targetURL = strings.TrimRight(u, "/") + "/" + strings.ToLower(method)
				}
				req, _ := http.NewRequest(method, targetURL, body)
				resp, err := doSelfTestRequest(client, req, testAuthCfg, cfg.TestAuth)
				if err != nil {
					errs <- err
					return
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode >= 400 {
					errs <- fmt.Errorf("%s %s: %s", method, u, resp.Status)
				}
			}(u, method)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

func doSelfTestRequest(client *http.Client, req *http.Request, authCfg config.Config, testAuth bool) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	proxyAuth := ""
	if testAuth {
		proxyAuth = proxy.UpstreamProxyAuthHeader(authCfg, req.Method, req.URL.String(), nil)
	}
	var lastResp *http.Response
	for attempts := 0; attempts < 3; attempts++ {
		next := req.Clone(req.Context())
		if len(body) == 0 {
			next.Body = http.NoBody
		} else {
			next.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ContentLength = int64(len(body))
		next.Header = req.Header.Clone()
		if proxyAuth != "" {
			next.Header.Set("Proxy-Authorization", proxyAuth)
		}
		resp, err := client.Do(next)
		if err != nil || !testAuth || resp.StatusCode != http.StatusProxyAuthRequired {
			return resp, err
		}
		lastResp = resp
		challenges := resp.Header.Values("Proxy-Authenticate")
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		proxyAuth = proxy.UpstreamProxyAuthHeader(authCfg, req.Method, req.URL.String(), challenges)
		if proxyAuth == "" {
			return resp, nil
		}
	}
	return lastResp, nil
}

func selfTestURLs(test string) []string {
	if test == "all" || test == "1" {
		return []string{"http://httpbin.org", "https://httpbin.org"}
	}
	if strings.HasPrefix(test, "all:") {
		base := strings.TrimPrefix(test, "all:")
		if strings.Contains(base, "://") {
			return []string{base}
		}
		return []string{"http://" + base, "https://" + base}
	}
	return nil
}

func selfTestAllMode(test string) bool {
	return test == "all" || test == "1" || strings.HasPrefix(test, "all:")
}

func waitPort(listen string, port int) error {
	addr := net.JoinHostPort(listenForClient(listen), fmt.Sprint(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("proxy did not start at %s", addr)
}

func listenForClient(listen string) string {
	for _, raw := range strings.Split(listen, ",") {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if host == "0.0.0.0" {
			return localhostIP
		}
		return host
	}
	return localhostIP
}
