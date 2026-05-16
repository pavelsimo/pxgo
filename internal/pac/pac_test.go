package pac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const simplePAC = `
function FindProxyForURL(url, host) {
  if (host == "direct.example.com") return "DIRECT";
  if (host == "proxy.example.com") return "PROXY proxy1.com:8080";
  if (host == "multi.example.com") return "PROXY proxy1.com:8080; PROXY proxy2.com:3128; DIRECT";
  if (host == "socks.example.com") return "SOCKS5 socks.com:1080";
  return "DIRECT";
}`

func TestPacFindProxyForURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.pac")
	if err := os.WriteFile(path, []byte(simplePAC), 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "utf-8")
	tests := []struct {
		host string
		want []string
	}{
		{"direct.example.com", []string{"DIRECT"}},
		{"proxy.example.com", []string{"proxy1.com:8080"}},
		{"multi.example.com", []string{"proxy1.com:8080", "proxy2.com:3128", "DIRECT"}},
		{"socks.example.com", []string{"socks5://socks.com:1080"}},
		{"unknown.example.com", []string{"DIRECT"}},
	}
	for _, tt := range tests {
		got := p.FindProxyForURL("http://"+tt.host, tt.host)
		for _, want := range tt.want {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: got %q missing %q", tt.host, got, want)
			}
		}
		if strings.Contains(got, "PROXY ") || strings.Contains(got, ";") {
			t.Fatalf("PAC output not normalized: %q", got)
		}
	}
	if !p.Loaded() {
		t.Fatal("PAC should be loaded")
	}
	p.Close()
	if p.Loaded() {
		t.Fatal("PAC should be closed")
	}
}

func TestPacLoadFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, simplePAC)
	}))
	defer srv.Close()
	p := New(srv.URL, "utf-8")
	got := p.FindProxyForURL("http://proxy.example.com", "proxy.example.com")
	if !strings.Contains(got, "proxy1.com:8080") {
		t.Fatalf("got %q", got)
	}
}

func TestPacURLFailureReturnsDirect(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	p := New(srv.URL, "utf-8")
	if got := p.FindProxyForURL("http://proxy.example.com", "proxy.example.com"); got != "DIRECT" {
		t.Fatalf("got %q", got)
	}
}

func TestBrokenPacReturnsDirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.pac")
	if err := os.WriteFile(path, []byte("this is not javascript {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "utf-8")
	if got := p.FindProxyForURL("http://example.com", "example.com"); got != "DIRECT" {
		t.Fatalf("got %q", got)
	}
}

func TestPacEncodingLatin1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "latin.pac")
	content := []byte("function FindProxyForURL(url, host) { var marker = '\xe9'; return \"DIRECT\"; }")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "latin-1")
	if got := p.FindProxyForURL("http://example.com", "example.com"); got != "DIRECT" {
		t.Fatalf("got %q", got)
	}
}

func TestPacWrongEncodingReturnsDirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-encoding.pac")
	utf16ish := []byte{0xff, 0xfe, 'f', 0, 'u', 0, 'n', 0, 'c', 0, 't', 0, 'i', 0, 'o', 0, 'n', 0}
	if err := os.WriteFile(path, utf16ish, 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "utf-8")
	if got := p.FindProxyForURL("http://example.com", "example.com"); got != "DIRECT" {
		t.Fatalf("got %q", got)
	}
}

func TestPacCallables(t *testing.T) {
	p := New("missing", "utf-8")
	if got := p.DNSResolve("localhost"); got != "127.0.0.1" {
		t.Fatalf("localhost resolved to %q", got)
	}
	if got := p.DNSResolve("this.host.definitely.does.not.exist.invalid"); got != "" {
		t.Fatalf("bad host resolved to %q", got)
	}
	if got := p.MyIPAddress(); got == "" {
		t.Fatal("myIpAddress returned empty")
	}
}

func TestPacMozillaUtilityFunctions(t *testing.T) {
	pacContent := `
function FindProxyForURL(url, host) {
  if (!dnsDomainIs(host, ".example.com")) return "DIRECT";
  if (dnsDomainLevels(host) != 2) return "DIRECT";
  if (!isPlainHostName("intranet")) return "DIRECT";
  if (!localHostOrDomainIs("www", "www.example.com")) return "DIRECT";
  if (!shExpMatch(url, "http://*.example.com/*")) return "DIRECT";
  if (!isInNet("10.1.2.3", "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (!isValidIpAddress("192.168.1.1")) return "DIRECT";
  if (isValidIpAddress("999.168.1.1")) return "DIRECT";
  return "PROXY util.proxy:8080";
}`
	path := filepath.Join(t.TempDir(), "utils.pac")
	if err := os.WriteFile(path, []byte(pacContent), 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "utf-8")
	got := p.FindProxyForURL("http://www.example.com/path", "www.example.com")
	if got != "util.proxy:8080" {
		t.Fatalf("got %q", got)
	}
}

func TestPacRangeUtilityFunctions(t *testing.T) {
	pacContent := `
function FindProxyForURL(url, host) {
  if (!weekdayRange("SUN", "SAT")) return "DIRECT";
  if (!dateRange(1, 31)) return "DIRECT";
  if (!timeRange(0, 23)) return "DIRECT";
  return "PROXY range.proxy:8080";
}`
	path := filepath.Join(t.TempDir(), "ranges.pac")
	if err := os.WriteFile(path, []byte(pacContent), 0o644); err != nil {
		t.Fatal(err)
	}
	p := New(path, "utf-8")
	got := p.FindProxyForURL("http://example.com/path", "example.com")
	if got != "range.proxy:8080" {
		t.Fatalf("got %q", got)
	}
}
