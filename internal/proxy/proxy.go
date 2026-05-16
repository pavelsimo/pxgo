package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp"
	"golang.org/x/crypto/md4"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/kerberos"
	"github.com/pavelsimo/pxgo/internal/wproxy"
)

const digestRealm = "PxClient"

type Server struct {
	cfg        config.Config
	w          *wproxy.Wproxy
	wmu        sync.RWMutex
	lastReload time.Time
	srv        *http.Server
	listeners  []net.Listener
	port       int
	stateMu    sync.RWMutex
	clientMu   sync.Mutex
	clientAuth map[string]bool
	ntlm       map[string][]byte
	ntlmSPNEGO map[string]bool
	krb        *kerberos.Manager
	closed     chan struct{}
	once       sync.Once
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
	return &Server{cfg: cfg, w: wp, lastReload: time.Now(), port: cfg.Port, clientAuth: map[string]bool{}, ntlm: map[string][]byte{}, ntlmSPNEGO: map[string]bool{}, krb: krb, closed: make(chan struct{})}, nil
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
	if !cfg.Kerberos || runtime.GOOS == "windows" {
		return nil, nil
	}
	if cfg.Username == "" {
		return nil, errors.New("--kerberos requires --username")
	}
	password := cfg.Password
	return kerberos.New(cfg.Username, func() *string {
		if password == "" {
			return nil
		}
		return &password
	}, kerberos.DetectHeimdal()), nil
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
	errc := make(chan error, len(listeners))
	for _, ln := range listeners {
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

func (s *Server) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if err := s.reloadProxyIfDue(); err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	s.reloadKerberos(false)
	if req.URL.Path == "/PxgoQuit" && req.Method == http.MethodGet {
		rw.WriteHeader(http.StatusOK)
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = s.Shutdown(context.Background())
		}()
		return
	}
	if !s.isClientAllowed(req.RemoteAddr) {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	if s.clientAuthEnabled() && !s.authenticateClient(req) {
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
		allow, _, _ := wproxy.ParseNoProxy(s.cfg.Allow, true)
		if allow.Contains(ip) {
			return true
		}
		if !s.cfg.Hostonly || s.cfg.Gateway {
			return false
		}
	}
	if s.cfg.Hostonly {
		for _, hostIP := range config.GetHostIPs() {
			if hostIP.Equal(ip) {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Server) reloadProxyIfDue() error {
	if s.cfg.ProxyReload <= 0 {
		return nil
	}
	s.wmu.RLock()
	if !s.proxyReloadableLocked() {
		s.wmu.RUnlock()
		return nil
	}
	due := time.Since(s.lastReload) >= time.Duration(s.cfg.ProxyReload)*time.Second
	s.wmu.RUnlock()
	if !due {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if !s.proxyReloadableLocked() {
		return nil
	}
	if time.Since(s.lastReload) < time.Duration(s.cfg.ProxyReload)*time.Second {
		return nil
	}
	wp, err := buildWproxy(s.cfg)
	if err != nil {
		return err
	}
	s.w = wp
	s.lastReload = time.Now()
	return nil
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
		return true
	}
	if !s.checkClientAuth(req) {
		return false
	}
	s.setClientAuthed(req.RemoteAddr)
	return true
}

func isBodyMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func (s *Server) isClientAuthed(remoteAddr string) bool {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	return s.clientAuth[remoteAddr]
}

func (s *Server) setClientAuthed(remoteAddr string) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	s.clientAuth[remoteAddr] = true
}

func (s *Server) clearClientAuthed(remoteAddr string) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	delete(s.clientAuth, remoteAddr)
}

func (s *Server) clearClientState(remoteAddr string) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	delete(s.clientAuth, remoteAddr)
	delete(s.ntlm, remoteAddr)
	delete(s.ntlmSPNEGO, remoteAddr)
}

func (s *Server) checkClientAuth(req *http.Request) bool {
	for _, auth := range clientAuthMethods(s.cfg.ClientAuth) {
		switch auth {
		case "BASIC":
			if s.checkBasicClientAuth(req) {
				return true
			}
		case "DIGEST":
			if s.checkDigestClientAuth(req) {
				return true
			}
		case "NTLM":
			if s.checkNTLMClientAuth(req, "NTLM") {
				return true
			}
		case "NEGOTIATE":
			// Full SPNEGO/GSS-API validation is platform-specific. Accept raw
			// NTLMSSP tokens carried under Negotiate when explicit client
			// credentials are configured.
			if s.checkNTLMClientAuth(req, "Negotiate") {
				return true
			}
		}
	}
	return false
}

func (s *Server) checkBasicClientAuth(req *http.Request) bool {
	h := req.Header.Get("Proxy-Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
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
	if !ok || !strings.EqualFold(scheme, "Digest") {
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
	return subtleEqualHex(response, expected)
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
	if strings.EqualFold(expectedScheme, "Negotiate") && !isNTLMSSP(raw) {
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
	for _, auth := range clientAuthMethods(s.cfg.ClientAuth) {
		switch auth {
		case "NEGOTIATE":
			if challenge := s.ntlmChallenge(req.RemoteAddr); len(challenge) != 0 {
				if s.ntlmChallengeUsesSPNEGO(req.RemoteAddr) {
					challenge = spnegoNegTokenResp(challenge)
				}
				challenges = append(challenges, `Negotiate `+base64.StdEncoding.EncodeToString(challenge))
			} else {
				challenges = append(challenges, `Negotiate`)
			}
		case "NTLM":
			if challenge := s.ntlmChallenge(req.RemoteAddr); len(challenge) != 0 {
				challenges = append(challenges, `NTLM `+base64.StdEncoding.EncodeToString(challenge))
			} else {
				challenges = append(challenges, `NTLM`)
			}
		case "DIGEST":
			challenges = append(challenges, `Digest realm="`+digestRealm+`", nonce="`+digestNonce(req.RemoteAddr)+`", qop="auth", algorithm="MD5"`)
		case "BASIC":
			challenges = append(challenges, `Basic realm="`+digestRealm+`"`)
		}
	}
	return challenges
}

func (s *Server) setNTLMChallenge(remoteAddr string, challenge []byte, usesSPNEGO bool) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	s.ntlm[remoteAddr] = challenge
	s.ntlmSPNEGO[remoteAddr] = usesSPNEGO
}

func (s *Server) ntlmChallenge(remoteAddr string) []byte {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	challenge := s.ntlm[remoteAddr]
	return append([]byte(nil), challenge...)
}

func (s *Server) clearNTLMChallenge(remoteAddr string) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	delete(s.ntlm, remoteAddr)
	delete(s.ntlmSPNEGO, remoteAddr)
}

func (s *Server) ntlmChallengeUsesSPNEGO(remoteAddr string) bool {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	return s.ntlmSPNEGO[remoteAddr]
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
	out := []byte{tag}
	out = append(out, derLength(len(content))...)
	out = append(out, content...)
	return out
}

func derLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buf [4]byte
	i := len(buf)
	for n := length; n > 0; n >>= 8 {
		i--
		buf[i] = byte(n)
	}
	out := []byte{0x80 | byte(len(buf)-i)}
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
	h := md4.New()
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
	return len(clientAuthMethods(s.cfg.ClientAuth)) != 0
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
		case "NONE":
			return nil
		case "ANY":
			return []string{"NEGOTIATE", "NTLM", "DIGEST", "BASIC"}
		case "ANYSAFE":
			return []string{"NEGOTIATE", "NTLM", "DIGEST"}
		default:
			methods = append(methods, method)
		}
	}
	return methods
}

func isSupportedClientAuth(auth string) bool {
	switch auth {
	case "NEGOTIATE", "NTLM", "DIGEST", "BASIC":
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
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", ts, host, digestRealm)))
	raw := fmt.Sprintf("%d:%s", ts, hex.EncodeToString(sum[:]))
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func verifyDigestNonce(nonce, remoteAddr string) bool {
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return false
	}
	tsText, hash, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > 120*time.Second {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", ts, host, digestRealm)))
	return subtleEqualHex(hash, hex.EncodeToString(sum[:]))
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
	sum := md5.Sum([]byte(s))
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
		scheme := "http"
		targetURL = scheme + "://" + req.Host + req.URL.RequestURI()
	}
	proxies, _, _, err := s.currentWproxy().FindProxyForURL(targetURL)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	incomingProxyAuth := req.Header.Get("Proxy-Authorization")
	resp, err := s.roundTripHTTPWithProxyFallback(req, u, body, targetURL, incomingProxyAuth, proxies)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

func (s *Server) roundTripHTTPWithProxyFallback(req *http.Request, u *url.URL, body []byte, targetURL, incomingProxyAuth string, proxies []wproxy.Server) (*http.Response, error) {
	candidates := proxyCandidates(proxies)
	var lastErr error
	for _, candidate := range candidates {
		transport := s.httpTransportForProxy(candidate)
		usesUpstreamProxy := candidate != wproxy.Direct
		outReq := s.newOutboundRequest(req, u, body, "")
		if usesUpstreamProxy {
			if auth := upstreamProxyAuthHeader(s.cfg, req.Method, targetURL, "", incomingProxyAuth); auth != "" {
				outReq.Header.Set("Proxy-Authorization", auth)
			}
		}
		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			lastErr = err
			continue
		}
		if usesUpstreamProxy && resp.StatusCode == http.StatusProxyAuthRequired {
			resp = s.retryHTTPProxyAuth(transport, req, u, body, targetURL, incomingProxyAuth, resp)
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no proxy candidates")
	}
	return nil, lastErr
}

func (s *Server) httpTransportForProxy(p wproxy.Server) *http.Transport {
	timeout := time.Duration(s.cfg.SockTimeout * float64(time.Second))
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}
	if p == wproxy.Direct {
		return transport
	}
	scheme := proxyScheme(p)
	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
	if strings.HasPrefix(scheme, "socks") {
		transport.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialSOCKSProxy(ctx, scheme, addr, target, timeout)
		}
	} else {
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: scheme, Host: addr})
	}
	return transport
}

func proxyCandidates(proxies []wproxy.Server) []wproxy.Server {
	if len(proxies) == 0 {
		return []wproxy.Server{wproxy.Direct}
	}
	return proxies
}

func (s *Server) retryHTTPProxyAuth(transport *http.Transport, req *http.Request, u *url.URL, body []byte, targetURL, passthroughAuth string, resp *http.Response) *http.Response {
	for attempts := 0; attempts < 3 && resp.StatusCode == http.StatusProxyAuthRequired; attempts++ {
		challenge := selectProxyAuthenticateChallenge(s.cfg.Auth, resp.Header.Values("Proxy-Authenticate"))
		auth := upstreamProxyAuthHeader(s.cfg, req.Method, targetURL, challenge, passthroughAuth)
		if auth == "" {
			s.forceKerberosReloadForUpstreamAuth(resp)
			return resp
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		nextReq := s.newOutboundRequest(req, u, body, auth)
		nextResp, err := transport.RoundTrip(nextReq)
		if err != nil {
			return resp
		}
		resp = nextResp
	}
	s.forceKerberosReloadForUpstreamAuth(resp)
	return resp
}

func (s *Server) newOutboundRequest(req *http.Request, u *url.URL, body []byte, proxyAuth string) *http.Request {
	outReq := req.Clone(req.Context())
	outReq.URL = u
	outReq.RequestURI = ""
	if len(body) == 0 {
		outReq.Body = http.NoBody
	} else {
		outReq.Body = io.NopCloser(bytes.NewReader(body))
	}
	outReq.ContentLength = int64(len(body))
	outReq.Header = cloneHeader(req.Header)
	stripProxyHeaders(outReq.Header)
	if s.cfg.UserAgent != "" {
		outReq.Header.Set("User-Agent", s.cfg.UserAgent)
	}
	if proxyAuth != "" {
		outReq.Header.Set("Proxy-Authorization", proxyAuth)
	}
	return outReq
}

func stripProxyHeaders(header http.Header) {
	for key := range header {
		if strings.HasPrefix(strings.ToLower(key), "proxy-") {
			header.Del(key)
		}
	}
}

func (s *Server) handleConnect(rw http.ResponseWriter, req *http.Request) {
	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	proxies, _, _, err := s.currentWproxy().FindProxyForURL("https://" + target)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	var upstream net.Conn
	upstream, err = s.connectWithProxyFallback(target, req.Header.Get("Proxy-Authorization"), proxies)
	if err != nil {
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
	_ = brw.Flush()
	go relay(client, upstream, time.Duration(s.cfg.Idle)*time.Second)
}

func (s *Server) connectWithProxyFallback(target, incomingProxyAuth string, proxies []wproxy.Server) (net.Conn, error) {
	timeout := time.Duration(s.cfg.SockTimeout * float64(time.Second))
	var lastErr error
	for _, p := range proxyCandidates(proxies) {
		var upstream net.Conn
		var err error
		if p == wproxy.Direct {
			upstream, err = net.DialTimeout("tcp", target, timeout)
		} else {
			addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
			switch scheme := proxyScheme(p); {
			case scheme == "https":
				upstream, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{ServerName: p.Host})
				if err == nil {
					err = s.sendUpstreamConnect(upstream, target, incomingProxyAuth)
				}
			case strings.HasPrefix(scheme, "socks"):
				upstream, err = dialSOCKSProxy(context.Background(), scheme, addr, target, timeout)
			default:
				upstream, err = net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					err = s.sendUpstreamConnect(upstream, target, incomingProxyAuth)
				}
			}
		}
		if err == nil {
			return upstream, nil
		}
		if upstream != nil {
			_ = upstream.Close()
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no proxy candidates")
	}
	return nil, lastErr
}

func (s *Server) forceKerberosReloadForUpstreamAuth(resp *http.Response) {
	if s.krb == nil || resp == nil || resp.StatusCode != http.StatusProxyAuthRequired {
		return
	}
	if findProxyAuthenticateChallenge(resp.Header.Values("Proxy-Authenticate"), "NEGOTIATE") == "" {
		return
	}
	s.reloadKerberos(true)
}

func proxyScheme(server wproxy.Server) string {
	if server.Scheme == "" {
		return "http"
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
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
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
	req := []byte{0x04, 0x01}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
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

func (s *Server) sendUpstreamConnect(conn net.Conn, target string, passthroughAuth string) error {
	return sendUpstreamConnectWithAuth(conn, target, s.cfg, "", passthroughAuth, s.forceKerberosReloadForUpstreamAuth)
}

func sendUpstreamConnectWithAuth(conn net.Conn, target string, cfg config.Config, challenge, passthroughAuth string, onAuthFailure func(*http.Response)) error {
	return sendUpstreamConnectAttempt(conn, target, cfg, challenge, passthroughAuth, 0, onAuthFailure)
}

func sendUpstreamConnectAttempt(conn net.Conn, target string, cfg config.Config, challenge, passthroughAuth string, attempts int, onAuthFailure func(*http.Response)) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth := upstreamProxyAuthHeader(cfg, http.MethodConnect, target, challenge, passthroughAuth); auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", auth)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
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
		if auth := upstreamProxyAuthHeader(cfg, http.MethodConnect, target, nextChallenge, passthroughAuth); auth != "" {
			return sendUpstreamConnectAttempt(conn, target, cfg, nextChallenge, passthroughAuth, attempts+1, onAuthFailure)
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
	if authMode == "DIGEST" {
		if !strings.HasPrefix(challenge, "Digest ") {
			return ""
		}
		params := parseAuthParams(strings.TrimPrefix(challenge, "Digest "))
		realm := params["realm"]
		nonce := params["nonce"]
		qop := selectDigestQop(params["qop"])
		if realm == "" || nonce == "" {
			return ""
		}
		nc := "00000001"
		cnonce := "pxgocnonce"
		ha1 := md5hex(cfg.Username + ":" + realm + ":" + cfg.Password)
		ha2 := md5hex(method + ":" + uri)
		if qop == "" {
			response := md5hex(ha1 + ":" + nonce + ":" + ha2)
			return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
				cfg.Username, realm, nonce, uri, response)
		}
		response := md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
		return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
			cfg.Username, realm, nonce, uri, qop, nc, cnonce, response)
	}
	if isConnectionAuth(authMode) {
		auth, _ := connectionProxyAuthHeader(cfg, authMode, challenge)
		return auth
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password))
}

func selectDigestQop(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "auth") {
			return "auth"
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
	if auth == "" || auth == "ANY" {
		return []string{"NEGOTIATE", "NTLM", "DIGEST", "BASIC"}
	}
	if auth == "NONE" {
		return nil
	}
	if auth == "ANYSAFE" {
		return []string{"NEGOTIATE", "NTLM", "DIGEST"}
	}
	for _, prefix := range []struct {
		name string
		base []string
		only bool
	}{
		{"SAFENO", []string{"NEGOTIATE", "NTLM", "DIGEST"}, false},
		{"ONLY", []string{"NEGOTIATE", "NTLM", "DIGEST", "BASIC"}, true},
		{"NO", []string{"NEGOTIATE", "NTLM", "DIGEST", "BASIC"}, false},
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
	if auth == "" || auth == "ANY" || auth == "ANYSAFE" || auth == "NONE" {
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
	case "NEGOTIATE", "NTLM", "DIGEST", "BASIC":
		return true
	default:
		return false
	}
}

func isConnectionAuth(auth string) bool {
	return strings.EqualFold(auth, "NTLM") || strings.EqualFold(auth, "NEGOTIATE")
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
		if strings.EqualFold(authMode, "NEGOTIATE") {
			msg = spnegoNegTokenInit(msg)
		}
		return canonicalConnectionAuthScheme(scheme) + " " + base64.StdEncoding.EncodeToString(msg), nil
	}
	challenge, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", err
	}
	wrapResponse := false
	if strings.EqualFold(authMode, "NEGOTIATE") && !isNTLMSSP(challenge) {
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
	if strings.EqualFold(scheme, "NTLM") {
		return "NTLM"
	}
	return "Negotiate"
}

func relay(a, b net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if idle > 0 {
			src = idleConn{Conn: src, idle: idle}
		}
		_, _ = io.Copy(dst, src)
		_ = dst.SetDeadline(time.Now())
		_ = src.SetDeadline(time.Now())
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
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
