package proxy

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- Digest and NTLM compatibility require MD5.
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck,gosec // NTLM compatibility requires MD4.

	"github.com/pavelsimo/pxgo/internal/debug"
)

// clientState holds per-connection auth state, keyed by RemoteAddr in
// Server.clients and dropped by the ConnState hook on close/hijack. Keeping
// state per connection means auth checks never contend on a global lock.
type clientState struct {
	authed     atomic.Bool
	mu         sync.Mutex // guards the NTLM handshake fields below
	ntlm       []byte
	ntlmSPNEGO bool
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
