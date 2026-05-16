# Architecture

The Go port is organized around one main binary and small internal packages.

## Runtime Flow

1. `main.go` parses configuration with `internal/config`.
2. The proxy server is created by `internal/proxy.New`.
3. Upstream proxy selection is delegated to `internal/wproxy`.
4. PAC files are loaded and evaluated by `internal/pac`.
5. HTTP requests are forwarded directly or through an upstream proxy.
6. HTTPS `CONNECT` requests create a tunnel between client and target or client
   and upstream proxy.
7. Optional upstream and client authentication is handled in `internal/proxy`.
8. Optional Kerberos ticket management is handled by `internal/kerberos`.

## Packages

| Path | Responsibility |
| --- | --- |
| `main.go` | CLI actions, self-test, startup install/uninstall dispatch |
| `internal/config` | Defaults, CLI/env/INI parsing, config save, password storage |
| `internal/proxy` | HTTP proxy, CONNECT tunnels, auth, allow rules, reload behavior |
| `internal/wproxy` | Proxy discovery model, manual proxy parsing, bypass rules |
| `internal/pac` | PAC loading, JavaScript execution, Mozilla PAC helper functions |
| `internal/kerberos` | `kinit`/`klist` orchestration and ticket refresh state |
| `internal/debug` | Debug logging |
| `internal/systemproxy` | Platform system proxy discovery |
| `internal/winstartup` | Windows startup command generation |

## State And Concurrency

The proxy server runs one `http.Server` over one or more listeners. Shared proxy
state is guarded by mutexes:

- listener/server/port state is guarded by `stateMu`
- PAC/system proxy reload state is guarded by `wmu`
- per-connection client auth state is guarded by `clientMu`
- Kerberos check and renewal state is guarded by the Kerberos manager mutex

The test suite includes race-detector coverage for the proxy and Kerberos
packages.

## Python Reference

The original Python implementation remains in `px-python/`. It is used as the
behavioral reference while the Go port replaces Python packaging, libcurl usage,
and Python-specific keyring integration with Go-native code.

