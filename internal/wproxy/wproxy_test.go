package wproxy

import (
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseProxy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Server
	}{
		{"empty", "", nil},
		{"single host port", "proxy.example.com:8080", []Server{{"proxy.example.com", 8080, "http"}}},
		{"single host default port", "proxy.example.com", []Server{{"proxy.example.com", 80, "http"}}},
		{"multiple", "proxy1.com:8080, proxy2.com:3128", []Server{{"proxy1.com", 8080, "http"}, {"proxy2.com", 3128, "http"}}},
		{"duplicates", "proxy.com:80, proxy.com:80", []Server{{"proxy.com", 80, "http"}}},
		{"spaces", "  proxy.com:80 , proxy2.com:3128  ", []Server{{"proxy.com", 80, "http"}, {"proxy2.com", 3128, "http"}}},
		{"schemes", "https://secure-proxy.example.com,socks5://socks.example.com", []Server{{"secure-proxy.example.com", 443, "https"}, {"socks.example.com", 1080, "socks5"}}},
		{"direct", "DIRECT", []Server{Direct}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProxy(tt.in)
			if err != nil {
				t.Fatalf("ParseProxy returned error: %v", err)
			}
			if len(tt.want) == 0 && len(got) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestParseProxyBadPort(t *testing.T) {
	if _, err := ParseProxy("proxy.com:notaport"); err == nil {
		t.Fatal("expected bad port error")
	}
}

func TestParseNoProxy(t *testing.T) {
	set, hosts, err := ParseNoProxy("127.0.0.1,example.com,10.0.0.0/8,192.168.*.*,192.168.1.1-192.168.1.10,<local>", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.9.9", "192.168.1.5"} {
		if !set.Contains(net.ParseIP(ip)) {
			t.Fatalf("expected %s in noproxy set", ip)
		}
	}
	if set.Contains(net.ParseIP("172.16.0.1")) {
		t.Fatal("unexpected 172.16.0.1 in noproxy set")
	}
	if !hosts["example.com"] || !hosts["localhost"] {
		t.Fatalf("missing hosts: %#v", hosts)
	}
}

func TestParseNoProxyIPOnlyRejectsHost(t *testing.T) {
	if _, _, err := ParseNoProxy("example.com", true); err == nil {
		t.Fatal("expected host rejection")
	}
}

func TestWproxyFindProxy(t *testing.T) {
	w, err := New(ModeConfig, []Server{{"proxy.com", 8080, "http"}}, "127.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	servers, _, _, err := w.FindProxyForURL("http://example.com/path?key=val")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(servers, []Server{{"proxy.com", 8080, "http"}}) {
		t.Fatalf("got %#v", servers)
	}
	servers, _, _, err = w.FindProxyForURL("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(servers, []Server{Direct}) {
		t.Fatalf("expected direct, got %#v", servers)
	}
}

func TestWproxyNoProxyHostSuffixBypassesProxy(t *testing.T) {
	w, err := New(ModeConfig, []Server{{"proxy.com", 8080, "http"}}, "example.com,.internal.test", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rawurl := range []string{"http://example.com", "http://api.example.com", "http://svc.internal.test"} {
		servers, _, _, err := w.FindProxyForURL(rawurl)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(servers, []Server{Direct}) {
			t.Fatalf("%s should bypass, got %#v", rawurl, servers)
		}
	}
	servers, _, _, err := w.FindProxyForURL("http://notexample.com")
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(servers, []Server{Direct}) {
		t.Fatalf("notexample.com should not bypass")
	}
}

func TestWproxyNoProxyStarBypassesAllHosts(t *testing.T) {
	w, err := New(ModeConfig, []Server{{"proxy.com", 8080, "http"}}, "*", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rawurl := range []string{"http://example.com", "http://another.invalid"} {
		servers, _, _, err := w.FindProxyForURL(rawurl)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(servers, []Server{Direct}) {
			t.Fatalf("%s should bypass, got %#v", rawurl, servers)
		}
	}
}

func TestWproxyNoProxyHostsStringCached(t *testing.T) {
	w, err := New(ModeConfig, []Server{{"proxy.com", 8080, "http"}}, "localhost,intranet.local", "")
	if err != nil {
		t.Fatal(err)
	}
	if w.NoProxyHostsStr == "" {
		t.Fatal("expected cached host string")
	}
	for _, want := range []string{"localhost", "intranet.local"} {
		if !strings.Contains(w.NoProxyHostsStr, want) {
			t.Fatalf("cached host string %q missing %q", w.NoProxyHostsStr, want)
		}
	}
}

func TestWproxyEnvProxyAndNoProxy(t *testing.T) {
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("no_proxy", "")
	t.Setenv("HTTP_PROXY", "envproxy.example.com:8888")
	t.Setenv("NO_PROXY", "127.0.0.1")
	w, err := New(ModeNone, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if w.Mode != ModeEnv {
		t.Fatalf("mode=%d", w.Mode)
	}
	servers, _, _, err := w.FindProxyForURL("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(servers, []Server{{"envproxy.example.com", 8888, "http"}}) {
		t.Fatalf("servers=%#v", servers)
	}
	servers, _, _, err = w.FindProxyForURL("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(servers, []Server{Direct}) {
		t.Fatalf("no_proxy did not bypass: %#v", servers)
	}
}

func TestWproxyNoEnvProxy(t *testing.T) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"} {
		old, ok := os.LookupEnv(key)
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(key, old)
			} else {
				_ = os.Unsetenv(key)
			}
		})
		_ = os.Unsetenv(key)
	}
	w, err := New(ModeNone, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if w.Mode != ModeNone {
		t.Fatalf("mode=%d", w.Mode)
	}
}

func TestGetNetloc(t *testing.T) {
	w, _ := New(ModeNone, nil, "", "")
	netloc, path, err := w.GetNetloc("https://example.com:8443/path?key=val")
	if err != nil {
		t.Fatal(err)
	}
	if netloc != (Server{"example.com", 8443, "https"}) {
		t.Fatalf("netloc = %#v", netloc)
	}
	if path != "/path?key=val" {
		t.Fatalf("path = %q", path)
	}
}

func TestGetNetlocRawHostPort(t *testing.T) {
	w, _ := New(ModeNone, nil, "", "")
	netloc, path, err := w.GetNetloc("example.com:8080")
	if err != nil {
		t.Fatal(err)
	}
	if netloc != (Server{"example.com", 8080, ""}) || path != "/" {
		t.Fatalf("netloc=%#v path=%q", netloc, path)
	}
}

func TestGetNetlocDefaultPorts(t *testing.T) {
	w, _ := New(ModeNone, nil, "", "")
	tests := []struct {
		rawurl string
		port   int
	}{
		{"http://example.com/page", 80},
		{"https://example.com/page", 443},
	}
	for _, tt := range tests {
		netloc, _, err := w.GetNetloc(tt.rawurl)
		if err != nil {
			t.Fatal(err)
		}
		if netloc != (Server{"example.com", tt.port, strings.Split(tt.rawurl, ":")[0]}) {
			t.Fatalf("%s netloc=%#v", tt.rawurl, netloc)
		}
	}
}
