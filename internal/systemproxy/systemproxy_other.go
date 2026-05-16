//go:build !windows

package systemproxy

func Discover() Config {
	return Config{}
}

func ResolveProxyForURL(rawurl string, cfg Config) (string, error) {
	return "", nil
}
