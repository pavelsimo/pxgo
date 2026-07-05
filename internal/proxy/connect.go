package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pavelsimo/pxgo/internal/config"
	"github.com/pavelsimo/pxgo/internal/debug"
	"github.com/pavelsimo/pxgo/internal/wproxy"
)

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
		pipelined, _ := brw.Peek(n)
		if _, err := upstream.Write(pipelined); err != nil {
			_ = upstream.Close()
			_ = client.Close()
			return
		}
		_, _ = brw.Discard(n)
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
