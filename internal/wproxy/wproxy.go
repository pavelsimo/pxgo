package wproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/pavelsimo/pxgo/internal/dnscache"
	"github.com/pavelsimo/pxgo/internal/pac"
	"github.com/pavelsimo/pxgo/internal/systemproxy"
)

const (
	ModeNone = iota
	ModeAuto
	ModePAC
	ModeManual
	ModeEnv
	ModeConfig
	ModeConfigPAC
)

const (
	directHost  = "DIRECT"
	directKey   = "direct://DIRECT:80"
	httpScheme  = "http"
	httpsScheme = "https"
)

var Direct = Server{Host: directHost, Port: 80, Scheme: "direct"}

type Server struct {
	Host   string
	Port   int
	Scheme string
}

type IPSet struct {
	nets   []*net.IPNet
	ranges [][2]net.IP
}

func (s *IPSet) AddCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return errors.New("bad ip")
		}
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			bits = 32
			ip = ip4
		}
		ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	s.nets = append(s.nets, ipnet)
	return nil
}

func (s *IPSet) AddRange(start, end string) error {
	a := net.ParseIP(start).To4()
	b := net.ParseIP(end).To4()
	if a == nil || b == nil {
		return errors.New("bad range")
	}
	s.ranges = append(s.ranges, [2]net.IP{a, b})
	return nil
}

func (s IPSet) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	// Ranges are IPv4-only (see AddRange).
	if ip4 := ip.To4(); ip4 != nil {
		for _, r := range s.ranges {
			if compareIP(ip4, r[0]) >= 0 && compareIP(ip4, r[1]) <= 0 {
				return true
			}
		}
	}
	return false
}

func (s IPSet) Size() int {
	return len(s.nets) + len(s.ranges)
}

func compareIP(a, b net.IP) int {
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func ParseProxy(proxystrs string) ([]Server, error) {
	var servers []Server
	seen := map[string]bool{}
	if strings.TrimSpace(proxystrs) == "" {
		return servers, nil
	}
	for _, item := range strings.Split(proxystrs, ",") {
		proxystr := strings.TrimSpace(item)
		if proxystr == "" {
			continue
		}
		if strings.EqualFold(proxystr, directHost) {
			if !seen[directKey] {
				servers = append(servers, Direct)
				seen[directKey] = true
			}
			continue
		}
		host := proxystr
		scheme := httpScheme
		port := 80
		if strings.Contains(proxystr, "://") {
			u, err := url.Parse(proxystr)
			if err != nil {
				return nil, err
			}
			if u.Scheme != "" {
				scheme = strings.ToLower(u.Scheme)
			}
			host = u.Hostname()
			switch {
			case u.Port() != "":
				port, err = strconv.Atoi(u.Port())
				if err != nil {
					return nil, fmt.Errorf("bad proxy server port: %s", u.Port())
				}
			case scheme == httpsScheme:
				port = 443
			case strings.HasPrefix(scheme, "socks"):
				port = 1080
			}
		} else if h, p, ok := strings.Cut(proxystr, ":"); ok {
			var err error
			host = strings.TrimSpace(h)
			port, err = strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				return nil, fmt.Errorf("bad proxy server port: %s", p)
			}
		}
		if strings.ContainsAny(host, " \t\r\n") {
			return nil, fmt.Errorf("bad proxy server host: %s", host)
		}
		key := fmt.Sprintf("%s://%s:%d", scheme, host, port)
		if !seen[key] {
			servers = append(servers, Server{Host: host, Port: port, Scheme: scheme})
			seen[key] = true
		}
	}
	return servers, nil
}

func ParseNoProxy(noproxystr string, iponly bool) (IPSet, map[string]bool, error) {
	set := IPSet{}
	hosts := map[string]bool{}
	if strings.TrimSpace(noproxystr) == "" {
		return set, hosts, nil
	}
	repl := strings.NewReplacer(";", ",", " ", ",")
	for _, raw := range strings.Split(repl.Replace(strings.ToLower(noproxystr)), ",") {
		bypass := strings.TrimSpace(raw)
		if bypass == "" {
			continue
		}
		if bypass == "<local>" {
			hosts["localhost"] = true
			_ = set.AddCIDR("127.0.0.0/8")
			continue
		}
		if bypass == "*" && !iponly {
			hosts[bypass] = true
			continue
		}
		var err error
		switch {
		case strings.Contains(bypass, "-"):
			a, b, _ := strings.Cut(bypass, "-")
			err = set.AddRange(a, b)
		case strings.Contains(bypass, "*"):
			err = addGlob(&set, bypass)
		default:
			err = set.AddCIDR(bypass)
		}
		if err == nil {
			continue
		}
		if iponly {
			return set, hosts, err
		}
		if !strings.Contains(bypass, "*") {
			hosts[bypass] = true
		}
	}
	return set, hosts, nil
}

func addGlob(set *IPSet, glob string) error {
	parts := strings.Split(glob, ".")
	if len(parts) != 4 {
		return errors.New("bad glob")
	}
	start := make([]string, 4)
	end := make([]string, 4)
	for i, p := range parts {
		if p == "*" {
			start[i] = "0"
			end[i] = "255"
		} else if _, err := strconv.Atoi(p); err == nil {
			start[i] = p
			end[i] = p
		} else {
			return errors.New("bad glob")
		}
	}
	return set.AddRange(strings.Join(start, "."), strings.Join(end, "."))
}

type Wproxy struct {
	Mode            int
	Servers         []Server
	NoProxy         IPSet
	NoProxyHosts    map[string]bool
	NoProxyHostsStr string
	PAC             *pac.Pac
}

func New(mode int, servers []Server, noproxy, pacEncoding string) (*Wproxy, error) {
	np, hosts, err := ParseNoProxy(noproxy, false)
	if err != nil {
		return nil, err
	}
	w := &Wproxy{Mode: mode, Servers: servers, NoProxy: np, NoProxyHosts: hosts}
	if mode == ModeConfigPAC && len(servers) > 0 {
		w.PAC = pac.New(servers[0].Host, pacEncoding)
	}
	if mode == ModeNone {
		if env := firstEnv("http_proxy", "HTTP_PROXY"); env != "" {
			parsed, err := ParseProxy(env)
			if err != nil {
				return nil, err
			}
			w.Mode = ModeEnv
			w.Servers = parsed
			if no := firstEnv("no_proxy", "NO_PROXY"); no != "" {
				np2, hosts2, _ := ParseNoProxy(no, false)
				w.NoProxy.nets = append(w.NoProxy.nets, np2.nets...)
				w.NoProxy.ranges = append(w.NoProxy.ranges, np2.ranges...)
				for h := range hosts2 {
					w.NoProxyHosts[h] = true
				}
			}
		}
		if w.Mode == ModeNone {
			sysproxy := systemproxy.Discover()
			switch {
			case sysproxy.Found && sysproxy.AutoDetect:
				w.Mode = ModeAuto
				mergeNoProxy(w, sysproxy.Bypass)
			case sysproxy.Found && sysproxy.IsPAC:
				w.Mode = ModePAC
				w.Servers = []Server{{Host: sysproxy.PACURL, Scheme: "pac"}}
				mergeNoProxy(w, sysproxy.Bypass)
			case sysproxy.Found:
				parsed, err := ParseProxy(sysproxy.ManualProxy)
				if err != nil {
					return nil, err
				}
				w.Mode = ModeManual
				w.Servers = parsed
				mergeNoProxy(w, sysproxy.Bypass)
			}
		}
	}
	var hostList []string
	for h := range w.NoProxyHosts {
		hostList = append(hostList, h)
	}
	w.NoProxyHostsStr = strings.Join(hostList, ",")
	return w, nil
}

func mergeNoProxy(w *Wproxy, noproxy string) {
	if noproxy == "" {
		return
	}
	np2, hosts2, _ := ParseNoProxy(noproxy, false)
	w.NoProxy.nets = append(w.NoProxy.nets, np2.nets...)
	w.NoProxy.ranges = append(w.NoProxy.ranges, np2.ranges...)
	for h := range hosts2 {
		w.NoProxyHosts[h] = true
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}
	return ""
}

func (w *Wproxy) GetNetloc(rawurl string) (Server, string, error) {
	if !strings.Contains(rawurl, "://") {
		host := rawurl
		port := 80
		if h, p, ok := strings.Cut(rawurl, ":"); ok {
			parsed, err := strconv.Atoi(p)
			if err != nil {
				return Server{}, "", fmt.Errorf("bad target port: %s", p)
			}
			host = h
			port = parsed
		}
		return Server{Host: host, Port: port}, "/", nil
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return Server{}, "", err
	}
	host := u.Hostname()
	if host == "" {
		host = rawurl
	}
	port := 0
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	} else {
		switch u.Scheme {
		case httpsScheme:
			port = 443
		case "ftp":
			port = 21
		default:
			port = 80
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return Server{Host: host, Port: port, Scheme: u.Scheme}, path, nil
}

func (w *Wproxy) FindProxyForURL(rawurl string) ([]Server, Server, string, error) {
	netloc, path, err := w.GetNetloc(rawurl)
	if err != nil {
		return nil, Server{}, "", err
	}
	if w.Mode == ModeNone {
		return []Server{Direct}, netloc, path, nil
	}
	if w.isNoProxy(netloc) {
		return []Server{Direct}, netloc, path, nil
	}
	if w.Mode == ModeConfigPAC && w.PAC != nil {
		out := w.PAC.FindProxyForURL(rawurl, netloc.Host)
		return parseProxyOrDirect(out), netloc, path, nil
	}
	if w.Mode == ModeAuto || w.Mode == ModePAC {
		cfg := systemproxy.Config{AutoDetect: w.Mode == ModeAuto, IsPAC: w.Mode == ModePAC}
		if w.Mode == ModePAC && len(w.Servers) > 0 {
			cfg.PACURL = w.Servers[0].Host
		}
		out, _ := systemproxy.ResolveProxyForURL(rawurl, cfg)
		if strings.TrimSpace(out) == "" {
			return []Server{Direct}, netloc, path, nil
		}
		return parseProxyOrDirect(out), netloc, path, nil
	}
	return append([]Server(nil), w.Servers...), netloc, path, nil
}

func parseProxyOrDirect(proxy string) []Server {
	servers, err := ParseProxy(proxy)
	if err != nil {
		return []Server{Direct}
	}
	return servers
}

func (w *Wproxy) isNoProxy(netloc Server) bool {
	host := strings.ToLower(netloc.Host)
	if w.hostMatchesNoProxy(host) {
		return true
	}
	if w.NoProxy.Size() == 0 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return w.NoProxy.Contains(ip)
	}
	for _, ip := range dnscache.Lookup(host) {
		if w.NoProxy.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Wproxy) hostMatchesNoProxy(host string) bool {
	for bypass := range w.NoProxyHosts {
		bypass = strings.TrimPrefix(strings.ToLower(bypass), ".")
		if bypass == "*" {
			return true
		}
		if host == bypass || strings.HasSuffix(host, "."+bypass) {
			return true
		}
	}
	return false
}
