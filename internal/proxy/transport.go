package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pavelsimo/pxgo/internal/wproxy"
)

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
