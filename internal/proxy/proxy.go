package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/debug"
	"github.com/pavelsimo/pxgo/internal/kerberos"
	"github.com/pavelsimo/pxgo/internal/wproxy"
)

const (
	digestRealm      = "PxClient"
	authAny          = "ANY"
	authAnySafe      = "ANYSAFE"
	authBasic        = "BASIC"
	authDigest       = "DIGEST"
	authNegotiate    = "NEGOTIATE"
	authNone         = "NONE"
	authNTLM         = "NTLM"
	authSchemeBasic  = "Basic"
	authSchemeDigest = "Digest"
	authSchemeNeg    = "Negotiate"
	digestQopAuth    = "auth"
	httpScheme       = "http"
	httpsScheme      = "https"
	maxMemoryBody    = 1 << 20
	goosWindows      = "windows"
)

type Server struct {
	cfg        config.Config
	w          *wproxy.Wproxy
	wmu        sync.RWMutex
	lastReload time.Time
	srv        *http.Server
	listeners  []net.Listener
	port       int
	stateMu    sync.RWMutex
	clients    sync.Map // remoteAddr string -> *clientState
	krb        *kerberos.Manager
	closed     chan struct{}
	once       sync.Once
	active     int64
	transports sync.Map // proxy key -> *http.Transport, reused across requests

	// Derived from immutable config once in New so request handlers do not
	// re-parse it on every call.
	clientAuthList []string
	allowSet       wproxy.IPSet
	hostIPs        atomic.Pointer[hostIPEntry]
}

// hostIPEntry caches the local interface addresses used by --hostonly checks;
// enumerating interfaces is a syscall storm we do not want per request.
type hostIPEntry struct {
	ips     []net.IP
	expires time.Time
}

func New(cfg config.Config) (*Server, error) {
	if err := validateUpstreamAuth(cfg.Auth); err != nil {
		return nil, err
	}
	if err := validateClientAuth(cfg.ClientAuth); err != nil {
		return nil, err
	}
	if err := validateAllow(cfg.Allow); err != nil {
		return nil, err
	}
	wp, err := buildWproxy(cfg)
	if err != nil {
		return nil, err
	}
	krb, err := buildKerberosManager(cfg)
	if err != nil {
		return nil, err
	}
	if krb != nil {
		krb.Check(true)
	}
	s := &Server{cfg: cfg, w: wp, lastReload: time.Now(), port: cfg.Port, krb: krb, closed: make(chan struct{})}
	s.clientAuthList = clientAuthMethods(cfg.ClientAuth)
	if cfg.Allow != "" {
		// Already validated by validateAllow above.
		s.allowSet, _, _ = wproxy.ParseNoProxy(cfg.Allow, true)
	}
	return s, nil
}

func validateAllow(allow string) error {
	if strings.TrimSpace(allow) == "" {
		return nil
	}
	if _, _, err := wproxy.ParseNoProxy(allow, true); err != nil {
		return fmt.Errorf("unsupported allow value: %w", err)
	}
	return nil
}

func buildWproxy(cfg config.Config) (*wproxy.Wproxy, error) {
	mode := wproxy.ModeNone
	var servers []wproxy.Server
	var err error
	if cfg.PAC != "" {
		mode = wproxy.ModeConfigPAC
		servers = []wproxy.Server{{Host: cfg.PAC, Port: 0, Scheme: "pac"}}
	} else if cfg.Server != "" {
		mode = wproxy.ModeConfig
		servers, err = wproxy.ParseProxy(cfg.Server)
		if err != nil {
			return nil, err
		}
	}
	wp, err := wproxy.New(mode, servers, cfg.NoProxy, cfg.PACEncoding)
	if err != nil {
		return nil, err
	}
	return wp, nil
}

func buildKerberosManager(cfg config.Config) (*kerberos.Manager, error) {
	if !cfg.Kerberos {
		return nil, nil
	}
	if cfg.Username == "" {
		return nil, errors.New("--kerberos requires --username")
	}
	mgr := kerberos.New(cfg.Username, func() *string {
		if password, ok := config.GetPassword(config.Realm, cfg.Username); ok {
			return &password
		}
		if cfg.Password == "" {
			return nil
		}
		return &cfg.Password
	}, kerberos.DetectHeimdal())
	if runtime.GOOS == goosWindows {
		failWithBackoff := func() bool {
			mgr.Backoff = kerberos.CheckInterval
			return false
		}
		mgr.KinitWithPasswordFunc = failWithBackoff
		mgr.KinitRenewFunc = failWithBackoff
		mgr.KlistValidFunc = func() bool { return false }
	}
	return mgr, nil
}

func (s *Server) ListenAddr() string {
	hosts := s.listenHosts()
	return fmt.Sprintf("%s:%d", hosts[0], s.Port())
}

func (s *Server) ListenAddrs() []string {
	hosts := s.listenHosts()
	addrs := make([]string, 0, len(hosts))
	port := s.Port()
	for _, host := range hosts {
		addrs = append(addrs, fmt.Sprintf("%s:%d", host, port))
	}
	return addrs
}

func (s *Server) listenHosts() []string {
	if s.cfg.Gateway || s.cfg.Hostonly {
		return []string{"0.0.0.0"}
	}
	seen := map[string]bool{}
	var hosts []string
	for _, raw := range strings.Split(s.cfg.Listen, ",") {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if !seen[host] {
			hosts = append(hosts, host)
			seen[host] = true
		}
	}
	if len(hosts) == 0 {
		hosts = append(hosts, "127.0.0.1")
	}
	return hosts
}

func (s *Server) Start() error {
	port := s.cfg.Port
	var listeners []net.Listener
	for _, host := range s.listenHosts() {
		addr := fmt.Sprintf("%s:%d", host, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
		if port == 0 {
			port = ln.Addr().(*net.TCPAddr).Port
		}
	}
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				s.clearClientState(conn.RemoteAddr().String())
			}
		},
	}
	s.stateMu.Lock()
	s.listeners = listeners
	s.port = port
	s.srv = srv
	s.stateMu.Unlock()
	go s.maintenanceLoop()
	errc := make(chan error, len(listeners))
	for _, ln := range listeners {
		debug.Dprint("listening on " + ln.Addr().String())
		go func(ln net.Listener) {
			err := srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				err = nil
			}
			errc <- err
		}(ln)
	}
	for range listeners {
		if err := <-errc; err != nil {
			_ = s.Shutdown(context.Background())
			return err
		}
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		s.stateMu.RLock()
		srv := s.srv
		s.stateMu.RUnlock()
		if srv != nil {
			err = srv.Shutdown(ctx)
		}
		s.clearTransports()
		if s.krb != nil {
			s.krb.Cleanup()
		}
		close(s.closed)
	})
	return err
}

func (s *Server) Port() int {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.port
}

func (s *Server) ActiveTunnels() int64 {
	return atomic.LoadInt64(&s.active)
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			debug.LogPanic(config.GetLogfile(config.LogCWD), recovered)
			http.Error(rw, "internal server error", http.StatusInternalServerError)
		}
	}()
	debug.Dprint(req.Method + " " + req.RequestURI)
	if !s.isClientAllowed(req.RemoteAddr) {
		debug.Dprint("client not allowed: " + req.RemoteAddr)
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	if req.URL.Path == "/PxgoQuit" && req.Method == http.MethodGet {
		rw.WriteHeader(http.StatusOK)
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = s.Shutdown(context.Background())
		}()
		return
	}
	if s.clientAuthEnabled() && !s.authenticateClient(req) {
		debug.Dprint("client auth required: " + req.RemoteAddr)
		s.clearClientAuthed(req.RemoteAddr)
		for _, challenge := range s.clientAuthChallenges(req) {
			rw.Header().Add("Proxy-Authenticate", challenge)
		}
		http.Error(rw, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(rw, req)
		return
	}
	s.handleHTTP(rw, req)
}

func (s *Server) isClientAllowed(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if s.cfg.Allow != "" && s.cfg.Allow != "*.*.*.*" && s.cfg.Allow != "0.0.0.0/0" {
		if s.allowSet.Contains(ip) {
			return true
		}
		if !s.cfg.Hostonly || s.cfg.Gateway {
			return false
		}
	}
	if s.cfg.Hostonly {
		for _, hostIP := range s.cachedHostIPs() {
			if hostIP.Equal(ip) {
				return true
			}
		}
		return false
	}
	return true
}

// cachedHostIPs refreshes lazily rather than via a background goroutine so
// Servers created without Shutdown (common in tests) do not leak a ticker.
func (s *Server) cachedHostIPs() []net.IP {
	if e := s.hostIPs.Load(); e != nil && time.Now().Before(e.expires) {
		return e.ips
	}
	ips := config.GetHostIPs()
	s.hostIPs.Store(&hostIPEntry{ips: ips, expires: time.Now().Add(30 * time.Second)})
	return ips
}

// maintenanceLoop runs time-based housekeeping (proxy reload, Kerberos ticket
// refresh) off the request path. It stops when Shutdown closes s.closed.
func (s *Server) maintenanceLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := s.reloadProxyIfDue(); err != nil {
				debug.Dprintf("proxy reload failed, keeping previous: %v", err)
			}
			s.reloadKerberos(false)
		case <-s.closed:
			return
		}
	}
}

func (s *Server) reloadProxyIfDue() error {
	if s.cfg.ProxyReload <= 0 {
		return nil
	}
	s.wmu.RLock()
	reloadable := s.proxyReloadableLocked()
	due := time.Since(s.lastReload) >= time.Duration(s.cfg.ProxyReload)*time.Second
	s.wmu.RUnlock()
	if !reloadable || !due {
		return nil
	}
	// buildWproxy may do network I/O (PAC download); keep it out of the lock
	// so in-flight requests are never stalled by a slow reload.
	wp, err := buildWproxy(s.cfg)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	changed := s.w == nil || wp.Mode != s.w.Mode || !equalServers(wp.Servers, s.w.Servers)
	s.w = wp
	s.lastReload = time.Now()
	s.wmu.Unlock()
	if changed {
		// Drop keep-alive pools only when the routing actually changed.
		s.clearTransports()
	}
	return nil
}

func equalServers(a, b []wproxy.Server) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) proxyReloadableLocked() bool {
	if s.w == nil {
		return false
	}
	if s.w.Mode == wproxy.ModeConfig || s.w.Mode == wproxy.ModeEnv {
		return false
	}
	if s.w.Mode == wproxy.ModeConfigPAC && !isHTTPURL(s.cfg.PAC) {
		return false
	}
	return true
}

func isHTTPURL(rawurl string) bool {
	lower := strings.ToLower(rawurl)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func (s *Server) reloadKerberos(force bool) {
	if s.krb != nil {
		s.krb.Check(force)
	}
}

func (s *Server) currentWproxy() *wproxy.Wproxy {
	s.wmu.RLock()
	defer s.wmu.RUnlock()
	return s.w
}

func (s *Server) handleHTTP(rw http.ResponseWriter, req *http.Request) {
	targetURL := req.URL.String()
	if !req.URL.IsAbs() {
		scheme := httpScheme
		targetURL = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	debug.Dprint("HTTP target: " + targetURL)
	proxies, _, _, err := s.currentWproxy().FindProxyForURL(targetURL)
	if err != nil {
		debug.Dprint("HTTP proxy lookup error: " + err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	debug.Dprintf("HTTP proxies: %v", proxies)
	u, err := url.Parse(targetURL)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	// Buffer the body only when it may be re-sent (proxy fallback or a 407
	// auth retry); otherwise stream it straight through.
	var body *replayableBody
	if s.needsReplayableBody(req, proxies) {
		body, err = newReplayableBody(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		defer body.Close()
	}
	incomingProxyAuth := req.Header.Get("Proxy-Authorization")
	resp, err := s.roundTripHTTPWithProxyFallback(req, u, body, targetURL, incomingProxyAuth, proxies)
	if err != nil {
		debug.Dprint("HTTP error: " + err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	debug.Dprintf("HTTP response: %d %s", resp.StatusCode, targetURL)
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

// needsReplayableBody reports whether the request body must be buffered so it
// can be re-sent. That is the case when more than one attempt may consume it:
// either proxy fallback across candidates (http.Transport closes the body even
// on a failed attempt, so a streamed body cannot be replayed), or an upstream
// 407 auth retry that can actually produce credentials.
func (s *Server) needsReplayableBody(req *http.Request, proxies []wproxy.Server) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return false
	}
	candidates := proxyCandidates(proxies)
	if len(candidates) > 1 {
		return true
	}
	if candidates[0] == wproxy.Direct {
		return false
	}
	if req.Header.Get("Proxy-Authorization") != "" {
		return true // passthrough auth is retried on 407
	}
	if len(upstreamAuthModes(s.cfg.Auth)) == 0 {
		return false // auth=NONE: never retried
	}
	if s.cfg.Username != "" && s.cfg.Password != "" {
		return true
	}
	return runtime.GOOS == goosWindows // SSPI may authenticate without configured credentials
}

func (s *Server) roundTripHTTPWithProxyFallback(req *http.Request, u *url.URL, body *replayableBody, targetURL, incomingProxyAuth string, proxies []wproxy.Server) (*http.Response, error) {
	candidates := proxyCandidates(proxies)
	var lastErr error
	for _, candidate := range candidates {
		if candidate == wproxy.Direct {
			debug.Dprint("HTTP: trying direct connection to " + targetURL)
		} else {
			debug.Dprintf("HTTP: trying proxy %s:%d for %s", candidate.Host, candidate.Port, targetURL)
		}
		transport := s.httpTransportForProxy(candidate)
		usesUpstreamProxy := candidate != wproxy.Direct
		outReq, err := s.newOutboundRequest(req, u, body, "")
		if err != nil {
			lastErr = err
			continue
		}
		if usesUpstreamProxy {
			if auth := upstreamProxyAuthHeader(s.cfg, req.Method, targetURL, "", incomingProxyAuth); auth != "" {
				outReq.Header.Set("Proxy-Authorization", auth)
			}
		}
		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			debug.Dprint("HTTP: proxy attempt failed: " + err.Error())
			lastErr = err
			continue
		}
		if usesUpstreamProxy && resp.StatusCode == http.StatusProxyAuthRequired {
			resp, err = s.retryHTTPProxyAuth(transport, req, u, body, targetURL, incomingProxyAuth, resp)
			if err != nil {
				return nil, err
			}
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no proxy candidates")
	}
	debug.Dprint("HTTP: all candidates failed: " + lastErr.Error())
	return nil, lastErr
}

func proxyCandidates(proxies []wproxy.Server) []wproxy.Server {
	if len(proxies) == 0 {
		return []wproxy.Server{wproxy.Direct}
	}
	return proxies
}

func (s *Server) newOutboundRequest(req *http.Request, u *url.URL, body *replayableBody, proxyAuth string) (*http.Request, error) {
	outReq := req.Clone(req.Context())
	outReq.URL = u
	outReq.RequestURI = ""
	if body != nil {
		rc, err := body.Open()
		if err != nil {
			return nil, err
		}
		outReq.Body = rc
		outReq.ContentLength = body.Size()
	} // else: stream req.Body as-is (single attempt, no replay needed)
	outReq.Header = cloneHeader(req.Header)
	stripProxyHeaders(outReq.Header)
	if s.cfg.UserAgent != "" {
		outReq.Header.Set("User-Agent", s.cfg.UserAgent)
	}
	if proxyAuth != "" {
		outReq.Header.Set("Proxy-Authorization", proxyAuth)
	}
	return outReq, nil
}

func stripProxyHeaders(header http.Header) {
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), "proxy-") {
			header.Del(key)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	copyHeader(out, h)
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
