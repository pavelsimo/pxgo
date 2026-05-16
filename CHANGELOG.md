# Changelog

All notable changes to pxgo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-16

### Added

- Initial Go rewrite of the Python px proxy
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

[Unreleased]: https://github.com/pavelsimo/pxgo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pavelsimo/pxgo/releases/tag/v0.1.0
