package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- Digest and NTLM compatibility require MD5.
	"crypto/rand"
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
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp"
	"golang.org/x/crypto/md4" //nolint:staticcheck,gosec // NTLM compatibility requires MD4.

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

// clientState holds per-connection auth state, keyed by RemoteAddr in
// Server.clients and dropped by the ConnState hook on close/hijack. Keeping
// state per connection means auth checks never contend on a global lock.
type clientState struct {
	authed     atomic.Bool
	mu         sync.Mutex // guards the NTLM handshake fields below
	ntlm       []byte
	ntlmSPNEGO bool
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

func (s *Server) authenticateClient(req *http.Request) bool {
	if req.Header.Get("Proxy-Authorization") == "" && s.isClientAuthed(req.RemoteAddr) {
		if isBodyMethod(req.Method) && req.ContentLength == 0 {
			return false
		}
		debug.Dprint("client already authenticated: " + req.RemoteAddr)
		return true
	}
	if !s.checkClientAuth(req) {
		return false
	}
	s.setClientAuthed(req.RemoteAddr)
	debug.Dprint("client authenticated: " + req.RemoteAddr)
	return true
}

func isBodyMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

// clientStateFor returns the state entry for remoteAddr, creating it if
// needed.
func (s *Server) clientStateFor(remoteAddr string) *clientState {
	if v, ok := s.clients.Load(remoteAddr); ok {
		return v.(*clientState)
	}
	v, _ := s.clients.LoadOrStore(remoteAddr, &clientState{})
	return v.(*clientState)
}

func (s *Server) isClientAuthed(remoteAddr string) bool {
	if v, ok := s.clients.Load(remoteAddr); ok {
		return v.(*clientState).authed.Load()
	}
	return false
}

func (s *Server) setClientAuthed(remoteAddr string) {
	s.clientStateFor(remoteAddr).authed.Store(true)
}

func (s *Server) clearClientAuthed(remoteAddr string) {
	if v, ok := s.clients.Load(remoteAddr); ok {
		v.(*clientState).authed.Store(false)
	}
}

func (s *Server) clearClientState(remoteAddr string) {
	s.clients.Delete(remoteAddr)
}

func (s *Server) checkClientAuth(req *http.Request) bool {
	for _, auth := range s.clientAuthList {
		switch auth {
		case authBasic:
			if s.checkBasicClientAuth(req) {
				debug.Dprint("client auth success: BASIC from " + req.RemoteAddr)
				return true
			}
		case authDigest:
			if s.checkDigestClientAuth(req) {
				debug.Dprint("client auth success: DIGEST from " + req.RemoteAddr)
				return true
			}
		case authNTLM:
			if s.checkNTLMClientAuth(req, authNTLM) {
				debug.Dprint("client auth success: NTLM from " + req.RemoteAddr)
				return true
			}
		case authNegotiate:
			// Full SPNEGO/GSS-API validation is platform-specific. Accept raw
			// NTLMSSP tokens carried under Negotiate when explicit client
			// credentials are configured.
			if s.checkNTLMClientAuth(req, authSchemeNeg) {
				debug.Dprint("client auth success: NEGOTIATE from " + req.RemoteAddr)
				return true
			}
		}
	}
	debug.Dprint("client auth failed from " + req.RemoteAddr)
	return false
}

func (s *Server) checkBasicClientAuth(req *http.Request) bool {
	h := req.Header.Get("Proxy-Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, authSchemeBasic) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	return (s.cfg.ClientUsername == "" || user == s.cfg.ClientUsername) && pass == s.cfg.ClientPassword
}

func (s *Server) checkDigestClientAuth(req *http.Request) bool {
	h := req.Header.Get("Proxy-Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, authSchemeDigest) {
		return false
	}
	params := parseAuthParams(strings.TrimSpace(token))
	username := params["username"]
	if username == "" || (s.cfg.ClientUsername != "" && username != s.cfg.ClientUsername) {
		return false
	}
	realm := params["realm"]
	nonce := params["nonce"]
	uri := params["uri"]
	response := params["response"]
	qop := params["qop"]
	nc := params["nc"]
	cnonce := params["cnonce"]
	if realm != digestRealm || uri == "" || response == "" || !verifyDigestNonce(nonce, req.RemoteAddr) {
		return false
	}
	ha1 := md5hex(username + ":" + realm + ":" + s.cfg.ClientPassword)
	ha2 := md5hex(req.Method + ":" + uri)
	var expected string
	if qop != "" {
		expected = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		expected = md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	if !subtleEqualHex(response, expected) {
		return false
	}
	// Reject replays of a verified nonce/nc pair (only detectable with qop,
	// where the client must increment nc per request).
	if qop != "" && digestNonceReplayed(nonce, nc) {
		return false
	}
	return true
}

func (s *Server) checkNTLMClientAuth(req *http.Request, expectedScheme string) bool {
	h := req.Header.Get("Proxy-Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, expectedScheme) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false
	}
	usesSPNEGO := false
	if strings.EqualFold(expectedScheme, authSchemeNeg) && !isNTLMSSP(raw) {
		unwrapped, ok := unwrapSPNEGONTLMToken(raw)
		if !ok {
			return false
		}
		raw = unwrapped
		usesSPNEGO = true
	}
	if !isNTLMSSP(raw) {
		return false
	}
	switch binary.LittleEndian.Uint32(raw[8:12]) {
	case 1:
		challenge, err := newNTLMChallenge()
		if err != nil {
			return false
		}
		s.setNTLMChallenge(req.RemoteAddr, challenge, usesSPNEGO)
		return false
	case 3:
		challenge := s.ntlmChallenge(req.RemoteAddr)
		if len(challenge) == 0 {
			return false
		}
		ok := verifyNTLMAuthenticate(raw, challenge, s.cfg.ClientUsername, s.cfg.ClientPassword)
		s.clearNTLMChallenge(req.RemoteAddr)
		return ok
	default:
		return false
	}
}

func (s *Server) clientAuthChallenges(req *http.Request) []string {
	var challenges []string
	for _, auth := range s.clientAuthList {
		switch auth {
		case authNegotiate:
			if challenge := s.ntlmChallenge(req.RemoteAddr); len(challenge) != 0 {
				if s.ntlmChallengeUsesSPNEGO(req.RemoteAddr) {
					challenge = spnegoNegTokenResp(challenge)
				}
				challenges = append(challenges, authSchemeNeg+" "+base64.StdEncoding.EncodeToString(challenge))
			} else {
				challenges = append(challenges, authSchemeNeg)
			}
		case authNTLM:
			if challenge := s.ntlmChallenge(req.RemoteAddr); len(challenge) != 0 {
				challenges = append(challenges, authNTLM+" "+base64.StdEncoding.EncodeToString(challenge))
			} else {
				challenges = append(challenges, authNTLM)
			}
		case authDigest:
			challenges = append(challenges, authSchemeDigest+` realm="`+digestRealm+`", nonce="`+digestNonce(req.RemoteAddr)+`", qop="auth", algorithm="MD5"`)
		case authBasic:
			challenges = append(challenges, authSchemeBasic+` realm="`+digestRealm+`"`)
		}
	}
	return challenges
}

func (s *Server) setNTLMChallenge(remoteAddr string, challenge []byte, usesSPNEGO bool) {
	cs := s.clientStateFor(remoteAddr)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.ntlm = challenge
	cs.ntlmSPNEGO = usesSPNEGO
}

// ntlmChallenge returns the stored challenge for remoteAddr. Callers must
// treat the returned slice as read-only.
func (s *Server) ntlmChallenge(remoteAddr string) []byte {
	v, ok := s.clients.Load(remoteAddr)
	if !ok {
		return nil
	}
	cs := v.(*clientState)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.ntlm
}

func (s *Server) clearNTLMChallenge(remoteAddr string) {
	v, ok := s.clients.Load(remoteAddr)
	if !ok {
		return
	}
	cs := v.(*clientState)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.ntlm = nil
	cs.ntlmSPNEGO = false
}

func (s *Server) ntlmChallengeUsesSPNEGO(remoteAddr string) bool {
	v, ok := s.clients.Load(remoteAddr)
	if !ok {
		return false
	}
	cs := v.(*clientState)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.ntlmSPNEGO
}

func isNTLMSSP(token []byte) bool {
	return len(token) >= 12 && string(token[:8]) == "NTLMSSP\x00"
}

var (
	spnegoOIDValue = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOIDValue   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func unwrapSPNEGONTLMToken(token []byte) ([]byte, bool) {
	if isNTLMSSP(token) {
		return token, true
	}
	if tag, content, rest, ok := readDERTLV(token); ok && tag == 0x60 && len(rest) == 0 {
		oidTag, oidContent, remainder, ok := readDERTLV(content)
		if !ok || oidTag != 0x06 || !sameBytes(oidContent, spnegoOIDValue) {
			return nil, false
		}
		token = remainder
	}
	tag, content, rest, ok := readDERTLV(token)
	if !ok || len(rest) != 0 || (tag != 0xa0 && tag != 0xa1) {
		return nil, false
	}
	seqTag, seqContent, seqRest, ok := readDERTLV(content)
	if !ok || seqTag != 0x30 || len(seqRest) != 0 {
		return nil, false
	}
	return findSPNEGONTLMToken(seqContent)
}

func findSPNEGONTLMToken(seq []byte) ([]byte, bool) {
	for len(seq) > 0 {
		tag, content, rest, ok := readDERTLV(seq)
		if !ok {
			return nil, false
		}
		seq = rest
		if tag != 0xa2 {
			continue
		}
		octetTag, octets, octetRest, ok := readDERTLV(content)
		if !ok || octetTag != 0x04 || len(octetRest) != 0 || !isNTLMSSP(octets) {
			return nil, false
		}
		return octets, true
	}
	return nil, false
}

func spnegoNegTokenInit(ntlmToken []byte) []byte {
	mechList := derTLV(0xa0, derTLV(0x30, derTLV(0x06, ntlmOIDValue)))
	mechToken := derTLV(0xa2, derTLV(0x04, ntlmToken))
	negTokenInit := derTLV(0xa0, derTLV(0x30, append(mechList, mechToken...)))
	return derTLV(0x60, append(derTLV(0x06, spnegoOIDValue), negTokenInit...))
}

func spnegoNegTokenResp(ntlmToken []byte) []byte {
	negState := derTLV(0xa0, derTLV(0x0a, []byte{0x01}))
	supportedMech := derTLV(0xa1, derTLV(0x06, ntlmOIDValue))
	responseToken := derTLV(0xa2, derTLV(0x04, ntlmToken))
	return derTLV(0xa1, derTLV(0x30, append(append(negState, supportedMech...), responseToken...)))
}

func readDERTLV(data []byte) (byte, []byte, []byte, bool) {
	if len(data) < 2 {
		return 0, nil, nil, false
	}
	tag := data[0]
	lengthByte := data[1]
	offset := 2
	length := int(lengthByte)
	if lengthByte&0x80 != 0 {
		count := int(lengthByte & 0x7f)
		if count == 0 || count > 4 || len(data) < offset+count {
			return 0, nil, nil, false
		}
		length = 0
		for i := 0; i < count; i++ {
			length = (length << 8) | int(data[offset+i])
		}
		offset += count
	}
	if length < 0 || len(data) < offset+length {
		return 0, nil, nil, false
	}
	return tag, data[offset : offset+length], data[offset+length:], true
}

func derTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 1+len(content)+4)
	out = append(out, tag)
	out = append(out, derLength(len(content))...)
	out = append(out, content...)
	return out
}

func derLength(length int) []byte {
	if length < 0 {
		return nil
	}
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf [4]byte
	i := len(buf)
	for n := length; n > 0; n >>= 8 {
		i--
		buf[i] = byte(n)
	}
	out := make([]byte, 0, 1+len(buf)-i)
	out = append(out, 0x80|byte(len(buf)-i))
	out = append(out, buf[i:]...)
	return out
}

func sameBytes(a, b []byte) bool {
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

func newNTLMChallenge() ([]byte, error) {
	serverChallenge := make([]byte, 8)
	if _, err := rand.Read(serverChallenge); err != nil {
		return nil, err
	}
	buf := make([]byte, 48)
	copy(buf, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:12], 2)
	binary.LittleEndian.PutUint32(buf[20:24], 0xa0888201)
	copy(buf[24:32], serverChallenge)
	return buf, nil
}

type ntlmAuthenticateMessage struct {
	lmResponse []byte
	ntResponse []byte
	domain     string
	user       string
}

func parseNTLMAuthenticateMessage(msg []byte) (ntlmAuthenticateMessage, error) {
	if len(msg) < 64 || string(msg[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		return ntlmAuthenticateMessage{}, errors.New("invalid NTLM authenticate message")
	}
	unicode := binary.LittleEndian.Uint32(msg[60:64])&1 != 0
	readField := func(offset int) ([]byte, error) {
		if offset+8 > len(msg) {
			return nil, errors.New("invalid NTLM field")
		}
		length := int(binary.LittleEndian.Uint16(msg[offset : offset+2]))
		start := int(binary.LittleEndian.Uint32(msg[offset+4 : offset+8]))
		if start < 0 || length < 0 || start+length > len(msg) {
			return nil, errors.New("NTLM field out of range")
		}
		return msg[start : start+length], nil
	}
	decode := func(data []byte) (string, error) {
		if unicode {
			return utf16leToString(data)
		}
		return string(data), nil
	}
	lm, err := readField(12)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	nt, err := readField(20)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	domainRaw, err := readField(28)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	userRaw, err := readField(36)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	domain, err := decode(domainRaw)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	user, err := decode(userRaw)
	if err != nil {
		return ntlmAuthenticateMessage{}, err
	}
	return ntlmAuthenticateMessage{lmResponse: lm, ntResponse: nt, domain: domain, user: user}, nil
}

func verifyNTLMAuthenticate(msg, challenge []byte, configuredUsername, password string) bool {
	if password == "" || len(challenge) < 32 {
		return false
	}
	parsed, err := parseNTLMAuthenticateMessage(msg)
	if err != nil || len(parsed.ntResponse) < 16 {
		return false
	}
	wantUser, wantDomain := splitConfiguredNTLMName(configuredUsername)
	if wantUser != "" && !strings.EqualFold(parsed.user, wantUser) {
		return false
	}
	if wantDomain != "" && !strings.EqualFold(parsed.domain, wantDomain) {
		return false
	}
	domainForHash := parsed.domain
	if wantDomain != "" {
		domainForHash = wantDomain
	}
	ntlmHash := ntlmHash(password)
	ntlmV2Hash := hmacMD5(ntlmHash, utf16le(strings.ToUpper(parsed.user)+domainForHash))
	expectedProof := hmacMD5(ntlmV2Hash, challenge[24:32], parsed.ntResponse[16:])
	if hmac.Equal(expectedProof, parsed.ntResponse[:16]) {
		return true
	}
	if len(parsed.lmResponse) >= 24 {
		expectedLM := hmacMD5(ntlmV2Hash, challenge[24:32], parsed.lmResponse[16:])
		return hmac.Equal(expectedLM, parsed.lmResponse[:16])
	}
	return false
}

func splitConfiguredNTLMName(username string) (user, domain string) {
	if before, after, ok := strings.Cut(username, `\`); ok {
		return after, before
	}
	return username, ""
}

func ntlmHash(password string) []byte {
	h := md4.New() // #nosec G406 -- NTLM uses MD4 by protocol design.
	_, _ = h.Write(utf16le(password))
	return h.Sum(nil)
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func utf16le(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	out := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

func utf16leToString(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", errors.New("odd UTF-16LE length")
	}
	encoded := make([]uint16, len(data)/2)
	for i := range encoded {
		encoded[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(encoded)), nil
}

func validateClientAuth(auth string) error {
	for _, method := range clientAuthMethods(auth) {
		if !isSupportedClientAuth(method) {
			return fmt.Errorf("unsupported client auth type: %s", auth)
		}
	}
	return nil
}

func (s *Server) clientAuthEnabled() bool {
	return len(s.clientAuthList) != 0
}

func clientAuthMethods(auth string) []string {
	auth = strings.TrimSpace(auth)
	if auth == "" {
		return nil
	}
	var methods []string
	for _, raw := range strings.Split(auth, ",") {
		method := strings.ToUpper(strings.TrimSpace(raw))
		switch method {
		case "":
			continue
		case authNone:
			return nil
		case authAny:
			return []string{authNegotiate, authNTLM, authDigest, authBasic}
		case authAnySafe:
			return []string{authNegotiate, authNTLM, authDigest}
		default:
			methods = append(methods, method)
		}
	}
	return methods
}

func isSupportedClientAuth(auth string) bool {
	switch auth {
	case authNegotiate, authNTLM, authDigest, authBasic:
		return true
	default:
		return false
	}
}

func digestNonce(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ts := time.Now().Unix()
	// The random salt makes each issued nonce unique, so nonce/nc replay
	// tracking cannot collide across clients behind the same address.
	salt := newCnonce()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s", ts, salt, host, digestRealm)))
	raw := fmt.Sprintf("%d:%s:%s", ts, salt, hex.EncodeToString(sum[:]))
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func verifyDigestNonce(nonce, remoteAddr string) bool {
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 {
		return false
	}
	tsText, salt, hash := parts[0], parts[1], parts[2]
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > digestNonceLifetime {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s", ts, salt, host, digestRealm)))
	return subtleEqualHex(hash, hex.EncodeToString(sum[:]))
}

// digestNonceLifetime bounds both client nonce validity and the retention of
// the digest bookkeeping maps below.
const digestNonceLifetime = 120 * time.Second

type digestNonceCount struct {
	count   atomic.Uint64
	created time.Time
}

var (
	digestNonceCounts sync.Map // upstream server nonce -> *digestNonceCount
	seenClientNonces  sync.Map // client "nonce|nc" -> expiry time.Time
	digestLastPrune   atomic.Int64
)

// nextDigestNC returns the next nonce-count for the given upstream server
// nonce, as RFC 7616 requires it to increment per request under one nonce.
func nextDigestNC(nonce string) string {
	v, _ := digestNonceCounts.LoadOrStore(nonce, &digestNonceCount{created: time.Now()})
	pruneDigestMaps()
	return fmt.Sprintf("%08x", v.(*digestNonceCount).count.Add(1))
}

// digestNonceReplayed records a verified client nonce/nc pair and reports
// whether it was already seen within the nonce lifetime.
func digestNonceReplayed(nonce, nc string) bool {
	_, loaded := seenClientNonces.LoadOrStore(nonce+"|"+nc, time.Now().Add(digestNonceLifetime))
	pruneDigestMaps()
	return loaded
}

// pruneDigestMaps drops expired entries from both digest maps, at most once
// per lifetime window, keeping them bounded without a background goroutine.
func pruneDigestMaps() {
	now := time.Now()
	last := digestLastPrune.Load()
	if now.Unix()-last < int64(digestNonceLifetime/time.Second) ||
		!digestLastPrune.CompareAndSwap(last, now.Unix()) {
		return
	}
	digestNonceCounts.Range(func(k, v any) bool {
		if now.Sub(v.(*digestNonceCount).created) > digestNonceLifetime {
			digestNonceCounts.Delete(k)
		}
		return true
	})
	seenClientNonces.Range(func(k, v any) bool {
		if now.After(v.(time.Time)) {
			seenClientNonces.Delete(k)
		}
		return true
	})
}

func newCnonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func parseAuthParams(header string) map[string]string {
	params := map[string]string{}
	for _, part := range splitAuthParams(header) {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		params[strings.ToLower(strings.TrimSpace(key))] = val
	}
	return params
}

func splitAuthParams(header string) []string {
	var parts []string
	start := 0
	inQuote := false
	for i, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				parts = append(parts, header[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, header[start:])
	return parts
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 -- HTTP Digest uses MD5 by protocol design.
	return hex.EncodeToString(sum[:])
}

func subtleEqualHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
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

// maxCachedTransports bounds the transport cache; a PAC file can emit an
// unbounded set of distinct proxies over time.
const maxCachedTransports = 64

func (s *Server) httpTransportForProxy(p wproxy.Server) *http.Transport {
	key := "direct"
	if p != wproxy.Direct {
		key = proxyScheme(p) + "://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	}
	if t, ok := s.transports.Load(key); ok {
		return t.(*http.Transport)
	}
	transport := s.newHTTPTransport(p)
	count := 0
	s.transports.Range(func(any, any) bool {
		count++
		return count < maxCachedTransports
	})
	if count >= maxCachedTransports {
		// Evict one arbitrary victim; clearing everything would force a full
		// reconnect for all warm upstreams because one new key showed up.
		s.transports.Range(func(k, v any) bool {
			v.(*http.Transport).CloseIdleConnections()
			s.transports.Delete(k)
			return false
		})
	}
	actual, _ := s.transports.LoadOrStore(key, transport)
	return actual.(*http.Transport)
}

func (s *Server) newHTTPTransport(p wproxy.Server) *http.Transport {
	timeout := time.Duration(s.cfg.SockTimeout * float64(time.Second))
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}
	if p == wproxy.Direct {
		return transport
	}
	scheme := proxyScheme(p)
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	if strings.HasPrefix(scheme, "socks") {
		transport.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialSOCKSProxy(ctx, scheme, addr, target, timeout)
		}
	} else {
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: scheme, Host: addr})
	}
	return transport
}

func (s *Server) clearTransports() {
	s.transports.Range(func(key, value any) bool {
		s.transports.Delete(key)
		value.(*http.Transport).CloseIdleConnections()
		return true
	})
}

func proxyCandidates(proxies []wproxy.Server) []wproxy.Server {
	if len(proxies) == 0 {
		return []wproxy.Server{wproxy.Direct}
	}
	return proxies
}

func (s *Server) retryHTTPProxyAuth(transport *http.Transport, req *http.Request, u *url.URL, body *replayableBody, targetURL, passthroughAuth string, resp *http.Response) (*http.Response, error) {
	if body == nil && req.Body != nil && req.Body != http.NoBody {
		// The body was streamed and cannot be replayed; pass the 407 through.
		s.forceKerberosReloadForUpstreamAuth(resp)
		return resp, nil
	}
	var session authSession
	var pinned *http.Transport
	// finish releases the pinned connection once the caller is done with the
	// final response body; closing it earlier would break the response.
	finish := func(r *http.Response) *http.Response {
		if pinned != nil && r != nil && r.Body != nil {
			r.Body = &transportClosingBody{ReadCloser: r.Body, transport: pinned}
		}
		return r
	}
	for attempts := 0; attempts < 3 && resp.StatusCode == http.StatusProxyAuthRequired; attempts++ {
		debug.Dprintf("HTTP proxy auth challenge (attempt %d): %s", attempts+1, targetURL)
		challenge := selectProxyAuthenticateChallenge(s.cfg.Auth, resp.Header.Values("Proxy-Authenticate"))
		if pinned == nil && isConnectionAuth(authSchemeFromChallenge(challenge)) {
			// NTLM/Negotiate handshakes must complete on one TCP connection;
			// a shared pooled transport could spread them across several.
			pinned = transport.Clone()
			pinned.MaxConnsPerHost = 1
			transport = pinned
		}
		var auth string
		switch {
		case session != nil:
			auth, _ = sspiSessionAuth(session, challenge)
		case isWindowsSSPICandidate(s.cfg, challenge):
			if sess, err := newSSPISession(); err == nil {
				session = sess
				auth, _ = session.Negotiate()
			}
		default:
			auth = upstreamProxyAuthHeader(s.cfg, req.Method, targetURL, challenge, passthroughAuth)
		}
		if auth == "" {
			s.forceKerberosReloadForUpstreamAuth(resp)
			return finish(resp), nil
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		nextReq, reqErr := s.newOutboundRequest(req, u, body, auth)
		if reqErr != nil {
			if pinned != nil {
				pinned.CloseIdleConnections()
			}
			return nil, reqErr
		}
		nextResp, roundTripErr := transport.RoundTrip(nextReq)
		if roundTripErr != nil {
			debug.Dprint("HTTP proxy auth retry failed: " + roundTripErr.Error())
			break
		}
		resp = nextResp
	}
	s.forceKerberosReloadForUpstreamAuth(resp)
	return finish(resp), nil
}

// transportClosingBody releases a single-connection pinned transport after the
// response body has been consumed and closed.
type transportClosingBody struct {
	io.ReadCloser
	transport *http.Transport
}

func (b *transportClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.transport.CloseIdleConnections()
	return err
}

// sspiSessionAuth picks Negotiate or Authenticate depending on whether the
// server challenge header contains a token.
func sspiSessionAuth(session authSession, challenge string) (string, error) {
	_, tokenPart, hasToken := strings.Cut(strings.TrimSpace(challenge), " ")
	if hasToken && strings.TrimSpace(tokenPart) != "" {
		return session.Authenticate(challenge)
	}
	return session.Negotiate()
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

type replayableBody struct {
	data []byte
	path string
	size int64
}

func newReplayableBody(src io.ReadCloser) (*replayableBody, error) {
	if src == nil || src == http.NoBody {
		return &replayableBody{}, nil
	}
	defer src.Close()

	var buf bytes.Buffer
	n, err := io.CopyN(&buf, src, maxMemoryBody+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if errors.Is(err, io.EOF) && n <= maxMemoryBody {
		return &replayableBody{data: buf.Bytes(), size: n}, nil
	}

	file, err := os.CreateTemp("", "pxgo-body-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	copied, err := io.Copy(file, src)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	cleanup = false
	return &replayableBody{path: path, size: n + copied}, nil
}

func (b *replayableBody) Open() (io.ReadCloser, error) {
	if b == nil || b.size == 0 {
		return http.NoBody, nil
	}
	if b.path != "" {
		return os.Open(b.path)
	}
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

func (b *replayableBody) Size() int64 {
	if b == nil {
		return 0
	}
	return b.size
}

func (b *replayableBody) Close() error {
	if b == nil || b.path == "" {
		return nil
	}
	err := os.Remove(b.path)
	b.path = ""
	return err
}

func stripProxyHeaders(header http.Header) {
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), "proxy-") {
			header.Del(key)
		}
	}
}

// connectTarget defaults the port to 443 when the CONNECT host has none,
// including bracketed IPv6 literals like "[::1]".
func connectTarget(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}
	return host
}

func (s *Server) handleConnect(rw http.ResponseWriter, req *http.Request) {
	target := connectTarget(req.Host)
	debug.Dprint("CONNECT target: " + target)
	proxies, _, _, err := s.currentWproxy().FindProxyForURL("https://" + target)
	if err != nil {
		debug.Dprint("CONNECT proxy lookup error: " + err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	debug.Dprintf("CONNECT proxies: %v", proxies)
	upstream, leftover, err := s.connectWithProxyFallback(target, req.Header.Get("Proxy-Authorization"), proxies)
	if err != nil {
		debug.Dprint("CONNECT failed: " + err.Error())
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(rw, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	// Bytes the upstream proxy sent behind its CONNECT response (e.g. a
	// server-speaks-first banner) belong to the tunnel; forward them.
	if len(leftover) > 0 {
		_, _ = brw.Write(leftover)
	}
	if err := brw.Flush(); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		return
	}
	// Bytes the client pipelined behind the CONNECT request (e.g. an eager
	// TLS ClientHello) are buffered in brw.Reader; relay reads the raw conn,
	// so forward them explicitly or they would be lost.
	if n := brw.Reader.Buffered(); n > 0 {
		pipelined, _ := brw.Reader.Peek(n)
		if _, err := upstream.Write(pipelined); err != nil {
			_ = upstream.Close()
			_ = client.Close()
			return
		}
		_, _ = brw.Reader.Discard(n)
	}
	debug.Dprint("CONNECT tunnel established: " + target)
	atomic.AddInt64(&s.active, 1)
	go func() {
		defer atomic.AddInt64(&s.active, -1)
		relay(client, upstream, time.Duration(s.cfg.Idle)*time.Second)
	}()
}

func (s *Server) connectWithProxyFallback(target, incomingProxyAuth string, proxies []wproxy.Server) (net.Conn, []byte, error) {
	timeout := time.Duration(s.cfg.SockTimeout * float64(time.Second))
	var lastErr error
	for _, p := range proxyCandidates(proxies) {
		var upstream net.Conn
		var leftover []byte
		var err error
		if p == wproxy.Direct {
			debug.Dprint("CONNECT: dialing direct to " + target)
			upstream, err = net.DialTimeout("tcp", target, timeout) // #nosec G704 -- this proxy must dial client-requested CONNECT targets.
		} else {
			addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
			debug.Dprintf("CONNECT: dialing via %s proxy %s for %s", proxyScheme(p), addr, target)
			switch scheme := proxyScheme(p); {
			case scheme == httpsScheme:
				upstream, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{ServerName: p.Host})
				if err == nil {
					leftover, err = s.sendUpstreamConnect(upstream, target, incomingProxyAuth)
				}
			case strings.HasPrefix(scheme, "socks"):
				upstream, err = dialSOCKSProxy(context.Background(), scheme, addr, target, timeout)
			default:
				upstream, err = net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					leftover, err = s.sendUpstreamConnect(upstream, target, incomingProxyAuth)
				}
			}
		}
		if err == nil {
			debug.Dprint("CONNECT: upstream connected to " + target)
			return upstream, leftover, nil
		}
		debug.Dprint("CONNECT: attempt failed: " + err.Error())
		if upstream != nil {
			_ = upstream.Close()
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no proxy candidates")
	}
	debug.Dprint("CONNECT: all candidates failed for " + target + ": " + lastErr.Error())
	return nil, nil, lastErr
}

func (s *Server) forceKerberosReloadForUpstreamAuth(resp *http.Response) {
	if s.krb == nil || resp == nil || resp.StatusCode != http.StatusProxyAuthRequired {
		return
	}
	if findProxyAuthenticateChallenge(resp.Header.Values("Proxy-Authenticate"), authNegotiate) == "" {
		return
	}
	s.reloadKerberos(true)
}

func proxyScheme(server wproxy.Server) string {
	if server.Scheme == "" {
		return httpScheme
	}
	return server.Scheme
}

func dialSOCKSProxy(ctx context.Context, scheme, proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	switch strings.ToLower(scheme) {
	case "socks4", "socks4a":
		return dialSOCKS4(ctx, proxyAddr, target, timeout)
	default:
		return dialSOCKS5(ctx, proxyAddr, target, timeout)
	}
}

func dialSOCKS5(ctx context.Context, proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 proxy rejected no-auth method")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	port16, err := socksPort(port)
	if err != nil {
		return nil, err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("SOCKS5 target host too long")
		}
		hostLen, err := socksHostLen(host)
		if err != nil {
			return nil, err
		}
		req = append(req, 0x03, hostLen)
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port16)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 connect failed with code %d", header[1])
	}
	var skip int
	switch header[3] {
	case 0x01:
		skip = 4
	case 0x03:
		lenb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenb); err != nil {
			return nil, err
		}
		skip = int(lenb[0])
	case 0x04:
		skip = 16
	default:
		return nil, fmt.Errorf("SOCKS5 bad address type %d", header[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnErr = false
	return conn, nil
}

func dialSOCKS4(ctx context.Context, proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	port16, err := socksPort(port)
	if err != nil {
		return nil, err
	}
	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, port16)
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(req, ip...)
		req = append(req, 0x00)
	} else {
		req = append(req, 0, 0, 0, 1, 0x00)
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[1] != 0x5a {
		return nil, fmt.Errorf("SOCKS4 connect failed with code %d", reply[1])
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnErr = false
	return conn, nil
}

func socksPort(port int) (uint16, error) {
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("SOCKS target port out of range: %d", port)
	}
	return uint16(port), nil
}

func socksHostLen(host string) (byte, error) {
	if len(host) > 255 {
		return 0, fmt.Errorf("SOCKS5 target host too long")
	}
	// #nosec G115 -- length is bounded above before conversion.
	return byte(len(host)), nil
}

func (s *Server) sendUpstreamConnect(conn net.Conn, target string, passthroughAuth string) ([]byte, error) {
	return sendUpstreamConnectWithAuth(conn, target, s.cfg, "", passthroughAuth, s.forceKerberosReloadForUpstreamAuth)
}

// sendUpstreamConnectWithAuth performs the CONNECT handshake with the upstream
// proxy and returns any tunnel bytes the upstream sent behind its response
// headers (they end up in the response reader's buffer and must be forwarded
// to the client, or server-speaks-first protocols would hang).
func sendUpstreamConnectWithAuth(conn net.Conn, target string, cfg config.Config, challenge, passthroughAuth string, onAuthFailure func(*http.Response)) ([]byte, error) {
	// One reader for all auth retry attempts: bytes buffered behind an
	// intermediate 407 must not be stranded in a discarded reader.
	reader := bufio.NewReader(conn)
	if err := sendUpstreamConnectAttempt(conn, reader, target, cfg, challenge, passthroughAuth, 0, nil, onAuthFailure); err != nil {
		return nil, err
	}
	if n := reader.Buffered(); n > 0 {
		leftover := make([]byte, n)
		_, _ = io.ReadFull(reader, leftover)
		return leftover, nil
	}
	return nil, nil
}

func sendUpstreamConnectAttempt(conn net.Conn, reader *bufio.Reader, target string, cfg config.Config, challenge, passthroughAuth string, attempts int, session authSession, onAuthFailure func(*http.Response)) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	var auth string
	if session != nil {
		auth, _ = sspiSessionAuth(session, challenge)
	} else {
		auth = upstreamProxyAuthHeader(cfg, http.MethodConnect, target, challenge, passthroughAuth)
	}
	if auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", auth)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return err
	}
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusProxyAuthRequired && attempts < 3 {
		nextChallenge := resp.Header.Get("Proxy-Authenticate")
		if selected := selectProxyAuthenticateChallenge(cfg.Auth, resp.Header.Values("Proxy-Authenticate")); selected != "" {
			nextChallenge = selected
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		nextSession := session
		if nextSession == nil && isWindowsSSPICandidate(cfg, nextChallenge) {
			if sess, err := newSSPISession(); err == nil {
				nextSession = sess
			}
		}
		if nextSession != nil {
			return sendUpstreamConnectAttempt(conn, reader, target, cfg, nextChallenge, passthroughAuth, attempts+1, nextSession, onAuthFailure)
		}
		if auth := upstreamProxyAuthHeader(cfg, http.MethodConnect, target, nextChallenge, passthroughAuth); auth != "" {
			return sendUpstreamConnectAttempt(conn, reader, target, cfg, nextChallenge, passthroughAuth, attempts+1, nil, onAuthFailure)
		}
	}
	if resp.StatusCode/100 != 2 {
		if onAuthFailure != nil {
			onAuthFailure(resp)
		}
		return fmt.Errorf("upstream CONNECT failed: %s", resp.Status)
	}
	return nil
}

func upstreamProxyAuthHeader(cfg config.Config, method, uri, challenge, passthroughAuth string) string {
	authModes := upstreamAuthModes(cfg.Auth)
	if len(authModes) == 0 {
		return passthroughAuth
	}
	if cfg.Username == "" || cfg.Password == "" {
		return ""
	}
	authMode := authModes[0]
	if len(authModes) > 1 {
		challengeScheme := authSchemeFromChallenge(challenge)
		if !containsAuthMode(authModes, challengeScheme) {
			return ""
		}
		authMode = challengeScheme
	}
	if authMode == authDigest {
		if !strings.HasPrefix(challenge, authSchemeDigest+" ") {
			return ""
		}
		params := parseAuthParams(strings.TrimPrefix(challenge, authSchemeDigest+" "))
		realm := params["realm"]
		nonce := params["nonce"]
		qop := selectDigestQop(params["qop"])
		if realm == "" || nonce == "" {
			return ""
		}
		ha1 := md5hex(cfg.Username + ":" + realm + ":" + cfg.Password)
		ha2 := md5hex(method + ":" + uri)
		if qop == "" {
			response := md5hex(ha1 + ":" + nonce + ":" + ha2)
			return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
				cfg.Username, realm, nonce, uri, response)
		}
		nc := nextDigestNC(nonce)
		cnonce := newCnonce()
		response := md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
		return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
			cfg.Username, realm, nonce, uri, qop, nc, cnonce, response)
	}
	if isConnectionAuth(authMode) {
		auth, _ := connectionProxyAuthHeader(cfg, authMode, challenge)
		return auth
	}
	return authSchemeBasic + " " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password))
}

func selectDigestQop(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		if strings.EqualFold(strings.TrimSpace(part), digestQopAuth) {
			return digestQopAuth
		}
	}
	return strings.TrimSpace(qop)
}

func UpstreamProxyAuthHeader(cfg config.Config, method, uri string, challenges []string) string {
	challenge := ""
	if len(challenges) != 0 {
		challenge = selectProxyAuthenticateChallenge(cfg.Auth, challenges)
	}
	return upstreamProxyAuthHeader(cfg, method, uri, challenge, "")
}

func upstreamAuthModes(auth string) []string {
	auth = strings.ToUpper(strings.TrimSpace(auth))
	if auth == "" || auth == authAny {
		return []string{authNegotiate, authNTLM, authDigest, authBasic}
	}
	if auth == authNone {
		return nil
	}
	if auth == authAnySafe {
		return []string{authNegotiate, authNTLM, authDigest}
	}
	for _, prefix := range []struct {
		name string
		base []string
		only bool
	}{
		{"SAFENO", []string{authNegotiate, authNTLM, authDigest}, false},
		{"ONLY", []string{authNegotiate, authNTLM, authDigest, authBasic}, true},
		{"NO", []string{authNegotiate, authNTLM, authDigest, authBasic}, false},
	} {
		if method, ok := strings.CutPrefix(auth, prefix.name); ok && isKnownAuthScheme(method) {
			if prefix.only {
				return []string{method}
			}
			return removeAuthMode(prefix.base, method)
		}
	}
	return []string{auth}
}

func validateUpstreamAuth(auth string) error {
	auth = strings.ToUpper(strings.TrimSpace(auth))
	if auth == "" || auth == authAny || auth == authAnySafe || auth == authNone {
		return nil
	}
	for _, prefix := range []string{"SAFENO", "ONLY", "NO"} {
		if method, ok := strings.CutPrefix(auth, prefix); ok && isKnownAuthScheme(method) {
			return nil
		}
	}
	if isKnownAuthScheme(auth) {
		return nil
	}
	return fmt.Errorf("unsupported upstream auth type: %s", auth)
}

func selectProxyAuthenticateChallenge(auth string, challenges []string) string {
	for _, scheme := range upstreamAuthModes(auth) {
		if challenge := findProxyAuthenticateChallenge(challenges, scheme); challenge != "" {
			return challenge
		}
	}
	return ""
}

func removeAuthMode(modes []string, remove string) []string {
	out := make([]string, 0, len(modes))
	for _, mode := range modes {
		if mode != remove {
			out = append(out, mode)
		}
	}
	return out
}

func containsAuthMode(modes []string, want string) bool {
	for _, mode := range modes {
		if strings.EqualFold(mode, want) {
			return true
		}
	}
	return false
}

func findProxyAuthenticateChallenge(challenges []string, scheme string) string {
	for _, challenge := range challenges {
		for _, part := range splitProxyAuthenticateValues(challenge) {
			if strings.EqualFold(authSchemeFromChallenge(part), scheme) {
				return strings.TrimSpace(part)
			}
		}
	}
	return ""
}

func splitProxyAuthenticateValues(header string) []string {
	var raw []string
	start := 0
	inQuote := false
	for i, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				raw = append(raw, header[start:i])
				start = i + 1
			}
		}
	}
	raw = append(raw, header[start:])
	var parts []string
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if isKnownAuthScheme(authSchemeFromChallenge(part)) || len(parts) == 0 {
			parts = append(parts, part)
			continue
		}
		parts[len(parts)-1] += ", " + part
	}
	return parts
}

func authSchemeFromChallenge(challenge string) string {
	scheme, _, _ := strings.Cut(strings.TrimSpace(challenge), " ")
	return strings.ToUpper(scheme)
}

func isKnownAuthScheme(scheme string) bool {
	switch strings.ToUpper(scheme) {
	case authNegotiate, authNTLM, authDigest, authBasic:
		return true
	default:
		return false
	}
}

func isConnectionAuth(auth string) bool {
	return strings.EqualFold(auth, authNTLM) || strings.EqualFold(auth, authNegotiate)
}

func connectionProxyAuthHeader(cfg config.Config, authMode, challengeHeader string) (string, error) {
	if cfg.Username == "" || cfg.Password == "" {
		return "", nil
	}
	scheme, token, _ := strings.Cut(strings.TrimSpace(challengeHeader), " ")
	if !strings.EqualFold(scheme, authMode) {
		return "", nil
	}
	if strings.TrimSpace(token) == "" {
		msg, err := ntlmssp.NewNegotiateMessage("", "")
		if err != nil {
			return "", err
		}
		if strings.EqualFold(authMode, authNegotiate) {
			msg = spnegoNegTokenInit(msg)
		}
		return canonicalConnectionAuthScheme(scheme) + " " + base64.StdEncoding.EncodeToString(msg), nil
	}
	challenge, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", err
	}
	wrapResponse := false
	if strings.EqualFold(authMode, authNegotiate) && !isNTLMSSP(challenge) {
		unwrapped, ok := unwrapSPNEGONTLMToken(challenge)
		if !ok {
			return "", nil
		}
		challenge = unwrapped
		wrapResponse = true
	}
	msg, err := ntlmssp.NewAuthenticateMessage(challenge, cfg.Username, cfg.Password, nil)
	if err != nil {
		return "", err
	}
	if wrapResponse {
		msg = spnegoNegTokenResp(msg)
	}
	return canonicalConnectionAuthScheme(scheme) + " " + base64.StdEncoding.EncodeToString(msg), nil
}

func canonicalConnectionAuthScheme(scheme string) string {
	if strings.EqualFold(scheme, authNTLM) {
		return authNTLM
	}
	return authSchemeNeg
}

// relay pumps bytes between the two ends of a CONNECT tunnel. Both conns stay
// raw (no reader wrappers) so io.Copy can use zero-copy paths (splice on
// Linux); idle detection is done with read deadlines instead. On a clean EOF
// only the destination's write side is closed, so the opposite direction can
// keep draining in-flight data (TCP half-close).
func relay(a, b net.Conn, idle time.Duration) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if copyDirection(dst, src, idle, &lastActivity) {
			halfClose(dst)
			return
		}
		// Real error or idle expiry: tear the whole tunnel down.
		_ = a.Close()
		_ = b.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// copyDirection copies src to dst until EOF, a real error, or tunnel-wide idle
// expiry. It reports whether the copy ended in a clean EOF. When idle > 0 each
// io.Copy call is bounded by a read deadline; on timeout the direction only
// gives up once the tunnel as a whole has been silent for the idle interval.
func copyDirection(dst, src net.Conn, idle time.Duration, lastActivity *atomic.Int64) bool {
	if idle <= 0 {
		_, err := io.Copy(dst, src)
		return err == nil
	}
	// Both directions' deadlines fire at the same instant, so a quiet
	// direction can observe staleness a moment before the active one records
	// its progress. A single short re-check closes that window.
	grace := idle / 10
	if grace > 100*time.Millisecond {
		grace = 100 * time.Millisecond
	}
	graced := false
	wait := idle
	for {
		_ = src.SetReadDeadline(time.Now().Add(wait))
		n, err := io.Copy(dst, src)
		if n > 0 {
			lastActivity.Store(time.Now().UnixNano())
		}
		if err == nil {
			return true // EOF
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return false
		}
		if time.Since(time.Unix(0, lastActivity.Load())) < idle {
			graced = false
			wait = idle
			continue
		}
		if !graced {
			graced = true
			wait = grace
			continue
		}
		return false // tunnel idle
	}
}

type closeWriter interface{ CloseWrite() error }

func halfClose(c net.Conn) {
	if cw, ok := c.(closeWriter); ok { // *net.TCPConn and *tls.Conn
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
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
