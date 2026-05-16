package systemproxy

import "strings"

type Config struct {
	ManualProxy string
	PACURL      string
	Bypass      string
	Found       bool
	IsPAC       bool
	AutoDetect  bool
}

func ParseManualProxyString(proxyServer string) string {
	var proxies []string
	for _, item := range strings.FieldsFunc(strings.ToLower(proxyServer), func(r rune) bool {
		return r == ';' || r == ' ' || r == ','
	}) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if scheme, proxy, ok := strings.Cut(item, "="); ok {
			scheme = strings.TrimSpace(scheme)
			proxy = strings.TrimSpace(proxy)
			switch scheme {
			case "ftp":
				continue
			case "socks":
				if !strings.Contains(proxy, "://") {
					proxy = "socks5://" + proxy
				}
			}
			proxies = append(proxies, proxy)
			continue
		}
		proxies = append(proxies, item)
	}
	seen := map[string]bool{}
	out := proxies[:0]
	for _, proxy := range proxies {
		if !seen[proxy] {
			out = append(out, proxy)
			seen[proxy] = true
		}
	}
	return strings.Join(out, ",")
}
