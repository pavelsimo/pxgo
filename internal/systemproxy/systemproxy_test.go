package systemproxy

import "testing"

func TestParseManualProxyString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"proxy.example.com:8080", "proxy.example.com:8080"},
		{"http=proxy1:8080;https=proxy2:8443", "proxy1:8080,proxy2:8443"},
		{"http=proxy1:8080; ftp=ftp-proxy:21; https=proxy2:8443", "proxy1:8080,proxy2:8443"},
		{"http=proxy1:8080; socks=socks-proxy:1080; ftp=ftp-proxy:21", "proxy1:8080,socks5://socks-proxy:1080"},
		{"http=proxy:8080;https=proxy:8080", "proxy:8080"},
		{"proxy1:8080 proxy2:8080;proxy3:8080,proxy4:8080", "proxy1:8080,proxy2:8080,proxy3:8080,proxy4:8080"},
	}
	for _, tt := range tests {
		if got := ParseManualProxyString(tt.in); got != tt.want {
			t.Fatalf("ParseManualProxyString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
