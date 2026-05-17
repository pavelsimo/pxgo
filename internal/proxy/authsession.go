package proxy

// authSession manages a stateful proxy authentication exchange.
// The Windows SSPI path (sspi_windows.go) implements it via the SSPI API.
// Non-SSPI auth uses upstreamProxyAuthHeader directly.
type authSession interface {
	// Negotiate returns the initial Proxy-Authorization header before a challenge arrives.
	Negotiate() (string, error)
	// Authenticate returns the Proxy-Authorization header in response to a server challenge header.
	Authenticate(challengeHeader string) (string, error)
}
