package proxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/debug"
)

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

func (s *Server) forceKerberosReloadForUpstreamAuth(resp *http.Response) {
	if s.krb == nil || resp == nil || resp.StatusCode != http.StatusProxyAuthRequired {
		return
	}
	if findProxyAuthenticateChallenge(resp.Header.Values("Proxy-Authenticate"), authNegotiate) == "" {
		return
	}
	s.reloadKerberos(true)
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
