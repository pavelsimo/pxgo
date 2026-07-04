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
| `internal/dnscache` | TTL cache in front of `net.LookupIP` (60 s hits, 5 s misses, 4096-entry cap), shared by noproxy matching and PAC `dnsResolve()` |
| `internal/kerberos` | `kinit`/`klist` orchestration and ticket refresh state |
| `internal/debug` | Debug logging |
| `internal/systemproxy` | Platform system proxy discovery |
| `internal/winstartup` | Windows startup command generation |

## State And Concurrency

The proxy server runs one `http.Server` over one or more listeners.

- listener/server/port state is guarded by `stateMu`
- the active wproxy is guarded by `wmu`; reloads rebuild outside the lock and
  swap under it, so requests never wait on a PAC download
- per-connection client auth state lives in a `sync.Map` of `clientState`
  entries keyed by remote address, dropped when the connection closes
- Kerberos check and renewal state is guarded by the Kerberos manager mutex

Time-based housekeeping (proxy reload, Kerberos ticket refresh) runs on a
background one-second ticker owned by `Start`/`Shutdown`, not on the request
path. A failed reload is logged and the previous proxy config stays active.

## Performance Notes

- `http.Transport`s are cached per proxy candidate (`DIRECT` or
  `scheme://host:port`, capped at 64) so upstream connections are reused via
  keep-alive; the cache is dropped only when a reload changes the routing.
- PAC scripts are compiled once to a `goja.Program`; evaluation draws VMs from
  a `sync.Pool`, so lookups run in parallel without a shared-VM lock.
- DNS lookups for noproxy matching and PAC `dnsResolve()` go through
  `internal/dnscache`.
- CONNECT relays keep both ends as raw `*net.TCPConn` so `io.Copy` can use
  `splice(2)` on Linux; idle detection uses read deadlines, and each direction
  half-closes independently (`CloseWrite`) so early EOF on one side does not
  truncate the other.

The test suite includes race-detector coverage for the proxy and Kerberos
packages.

## Python Reference

The original Python implementation remains in `px-python/`. It is used as the
behavioral reference while the Go port replaces Python packaging, libcurl usage,
and Python-specific keyring integration with Go-native code.

