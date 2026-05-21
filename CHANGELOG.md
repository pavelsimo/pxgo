# Changelog

All notable changes to pxgo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/pavelsimo/pxgo/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/pavelsimo/pxgo/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pavelsimo/pxgo/releases/tag/v0.1.0
