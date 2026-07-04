# Changelog

All notable changes to pxgo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Handle SIGINT/SIGTERM with a graceful, bounded shutdown that drains in-flight requests
- Add a benchmark harness: `make bench`, `scripts/bench-e2e.sh` (vs Python px), and `docs/benchmarking.md`

### Changed
- Reuse upstream connections via cached keep-alive transports keyed by proxy candidate
- Compile PAC scripts once and evaluate them on a pooled set of JavaScript VMs, removing the global PAC lock
- Cache DNS lookups used by `--noproxy` matching and PAC `dnsResolve()` (new `internal/dnscache`)
- Stream request bodies straight through unless an upstream auth retry could need a replay
- Rewrite the CONNECT relay to preserve the kernel `splice(2)` fast path and half-close each direction independently
- Run proxy reload and Kerberos ticket checks on a background ticker instead of per request; a failed reload now keeps the previous proxy config and logs the error instead of returning 502
- Reload the proxy configuration outside the routing lock and keep warm connections unless the routing actually changed

### Fixed
- Forward client bytes pipelined behind a CONNECT request (fixes stalled TLS handshakes)
- Deliver upstream bytes that arrive together with the CONNECT response (fixes server-speaks-first protocols such as SMTP)
- Pin NTLM/Negotiate upstream authentication to a single connection
- Match IPv6 addresses and CIDRs in `--noproxy` and `--allow`
- Default CONNECT requests to bracketed IPv6 literals without a port to port 443
- Bypass the whole `127.0.0.0/8` loopback block for `<local>`
- Send an incrementing nonce count and random cnonce in upstream Digest authentication
- Reject replayed client Digest nonce/nc pairs and add PAC fetch timeouts with retry backoff

## [0.4.0] - 2026-05-23

### Added
- Add WinGet release publishing so Windows users can install pxgo with `winget install pavelsimo.pxgo`

## [0.3.0] - 2026-05-23

### Fixed
- Keep active CONNECT downloads alive while the upload side is idle

## [0.2.0] - 2026-05-21

### Added
- Store and retrieve proxy credentials in the OS keyring (Windows Credential Manager, macOS Keychain, libsecret on Linux)
- Prompt for passwords interactively with no echo when `--password` or `--client-password` is used without a value
- Support Windows SSPI for transparent single-sign-on on domain-joined machines without explicit credentials
- Add `PXGO_KEYRING_PLAINTEXT=1` environment variable to use a plaintext credential file instead of the OS keyring (for Docker and CI)
- Buffer large request bodies without loading them fully into memory; uploads over 1 MiB spill to a temporary file
- Reload Windows system proxy settings on a configurable interval so VPN connect/disconnect changes take effect without restart

### Fixed
- Stop retrying upstream proxy candidates after the client has already disconnected
- Fix `--verbose` and `--log` flags not producing any proxy debug output

## [0.1.0] - 2026-05-16

### Added

- Initial Go rewrite of the Python Px proxy
- HTTP/HTTPS proxy with CONNECT tunnel support
- NTLM authentication via `go-ntlmssp`
- Kerberos authentication support (Linux/macOS)
- PAC file evaluation via `goja` JavaScript engine
- INI, environment variable, and dotenv configuration
- `--proxy`, `--pac`, `--port`, `--listen`, `--gateway`, `--hostonly` flags
- `--auth`, `--username`, `--client-auth`, `--client-username` auth flags
- `--noproxy` bypass list with IP ranges and CIDR support
- `--test` self-test mode with httpbin.org
- `--save` to persist config to pxgo.ini
- `--install`/`--uninstall` Windows registry startup integration
- `--quit` and `--restart` for running instances
- `--password`/`--client-password` keyring credential storage
- Docker support
- Multi-platform builds: Linux, macOS, Windows (amd64, arm64)

[Unreleased]: https://github.com/pavelsimo/pxgo/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pavelsimo/pxgo/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pavelsimo/pxgo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pavelsimo/pxgo/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pavelsimo/pxgo/releases/tag/v0.1.0
