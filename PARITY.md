# Feature Parity: px-python vs pxgo

Comparison of the Go rewrite against the original Python px proxy. Gaps where the Go version is weaker are noted with severity; areas where Go is ahead are listed at the bottom.

**Legend:** ✓ parity · ⚠ minor gap · ✗ significant gap · ☠ critical gap

---

## Critical Gaps

### ✓ Windows SSPI — RESOLVED

Python's libcurl uses Windows SSPI automatically for Negotiate/NTLM when no username is configured, enabling seamless single-sign-on on domain-joined machines (`handler.py:96-118`, `handler.py:701-703`).

Go now has SSPI support via `github.com/alexbrainman/sspi`. When running on Windows with no `--username` configured, both HTTP and CONNECT tunnels detect a Negotiate/NTLM proxy challenge and transparently authenticate using the current user's Windows credentials. The implementation lives in `internal/proxy/sspi_windows.go`; non-Windows builds use a no-op stub (`sspi_stub.go`).

`kerberos.go:128` still skips Kerberos on Windows — Kerberos ticket management is handled by SSPI transparently instead.

---

### ✓ Password Storage / Keyring — RESOLVED

Python's `--password` prompts interactively via `getpass.getpass()` and stores the result in the OS system keyring (Windows Credential Manager, macOS Keychain, libsecret on Linux). `config.py:493-511`.

Go now matches this behaviour:
- `--password` (no value) prompts interactively with no echo via `golang.org/x/term`.
- Passwords are stored in the OS keyring via `github.com/zalando/go-keyring` (Windows Credential Manager, macOS Keychain, libsecret). They are loaded automatically from the keyring when the matching username is provided at startup.
- `PXGO_KEYRING_PLAINTEXT=1` bypasses the OS keyring and uses a plaintext JSON file instead — useful for Docker and CI environments without a keyring daemon.

As a side effect, `--password` and `--client-password` now print a confirmation on success, closing the "Silent `--save` and `--password`" moderate gap.

---

## Significant Gaps

### ✗ Request Body Buffering (large uploads)

Python streams request bodies via h11 in 64 KB chunks (`handler.py:136, 531, 564`) and never fully buffers them in memory.

Go reads the entire request body into memory before forwarding (`handleHTTP:1026`):

```go
body, _ = io.ReadAll(req.Body)
```

A 500 MB upload consumes 500 MB of heap.

**Why:** Go's `http.Transport.RoundTrip` needs a re-readable body to support 407 auth retries (re-send the same body with credentials). Python's libcurl handles re-sends internally without exposing this constraint.

---

### ✗ workers / threads / foreground (parsed, not implemented)

Python's `workers=N` spawns N−1 child processes (`main.py:166-182`), each running a full asyncio event loop. `threads=N` sets the `ThreadPoolExecutor` size per process. `foreground=0` detaches the console on Windows.

In Go all three are parsed and stored but have no effect. Documented explicitly as "compatibility setting retained for config parity" in `docs/configuration.md:69-74`. Go uses one goroutine per connection with the runtime scheduler handling concurrency. No daemonization exists.

**Why:** Go's goroutine model makes workers/threads unnecessary. Daemon mode would require platform-specific `fork`/`setsid` logic or service-manager integration.

---

### ✗ System Proxy Reload

Python's `proxyreload` interval re-reads Windows Internet Options and system proxy settings every N seconds — useful when a VPN connects or disconnects.

Go's `proxyReloadableLocked()` (`proxy.go:350-361`) only reloads when the PAC source is an HTTP(S) URL. The `internal/systemproxy` package is called once at startup and is not wired into the reload loop.

**Why:** Likely an oversight; the systemproxy package exists but was never connected to the periodic reload path.

---

## Moderate Gaps

### ⚠ Kerberos: No Interactive Password Prompting

Python runs `kinit` via a PTY so it can respond to the password prompt interactively (`kerberos.py:137-142`, `fcntl.ioctl TIOCSCTTY`). The password is re-fetched from the keyring on each `kinit` attempt.

Go passes the password via a stdin pipe (`kerberos.go:185`). This works for most `kinit` implementations but may fail with interactive-only variants. The password is captured once at startup and not re-fetched.

---

### ⚠ Quit Robustness + Security

Python retries the quit request up to 5 times with polling and waits for the socket to fully close before confirming success (`config.py:240-312`). The `/PxQuit` handler validates the client IP against the allow list.

Go makes a single attempt with a 2-second timeout and no retry (`main.go:189-204`). The `/PxgoQuit` endpoint does **not** validate the client IP (`proxy.go:261-267`) — any host that can reach the port can trigger a remote shutdown.

---

### ⚠ Crash Recovery / Traceback Logging

Python installs a `sys.excepthook` that captures unhandled exceptions and writes a traceback to `debug.log` in the working directory even when logging is disabled (`main.py:318-331`).

Go has no equivalent. An unhandled panic prints to stderr and exits. The `recover()` in `debug.go:Pprint` only suppresses errors during log printing, not proxy panics.

---

## Minor Gaps

### ⚠ `--test` Method Coverage for Single URL

Python always tests GET, POST, PUT, DELETE, and PATCH regardless of mode.

Go tests only GET for a single `--test=URL`. All five methods are only exercised in all-mode (`--test=all` / `--test=all:base`). `main.go:233-236`.

---

### ⚠ Silent `--save` and `--password`

Python prints a confirmation and echoes the written config to stdout after `--save` (`config.py:672-683`), and prints prompts and success messages for `--password`.

Go is silent on success for both.

---

## Where Go Is Ahead

| Area | Detail |
| --- | --- |
| **Multi-proxy fallback** | Python only tries the first proxy in a comma-separated list. Go iterates all candidates (`roundTripHTTPWithProxyFallback`, `connectWithProxyFallback`). |
| **CONNECT auth** | Go implements an explicit 407 → retry loop with a full NTLM 3-way handshake for CONNECT tunnels (`proxy.go:1424-1465`). Python delegates this entirely to libcurl. |
| **SOCKS support** | Go has a native SOCKS4/SOCKS4a/SOCKS5 implementation (`proxy.go:1261-1407`). Python delegates to libcurl. |
| **Client disconnect handling** | Go short-circuits fallback attempts immediately on client disconnect (`roundTripHTTPWithProxyFallback`) rather than trying all candidates. |

---

## What Is at Parity

| Feature | Notes |
| --- | --- |
| Upstream auth schemes | NEGOTIATE, NTLM, DIGEST, BASIC, ANY, ANYSAFE, NO/SAFENO/ONLY prefixes |
| Client (downstream) auth | Same schemes; equivalent NTLM state machine |
| PAC file execution | Same helper functions (`dnsResolve`, `myIpAddress`, `alert`); same return-value parsing |
| HTTPS upstream proxy | Both support `https://` upstream proxy URLs |
| noproxy / allow rules | CIDR, wildcard, IP range, domain |
| Kerberos ticket lifecycle | Same check/renewal/retry intervals; Heimdal and MIT detection |
| Proxy reload for PAC URLs | HTTP(S) PAC sources reloaded on `proxyreload` interval |
| CONNECT tunneling | Idle timeout, bidirectional relay |
| Log levels 0-4 | `--verbose`, `--debug`, `--uniqlog`, `--log=N`, `PXGO_LOG=`, `settings:log=` |
| dotenv loading | CWD then script dir; same precedence |
| Windows startup install | Registry key, `--force` flag, `--uninstall` |
| Config INI save/load | All keys round-trip correctly |
| Quit / restart | Functionally equivalent (modulo robustness gap above) |
| Windows SSPI | Transparent SSO via `github.com/alexbrainman/sspi`; NTLM/Negotiate without explicit credentials |
| OS keyring + interactive password | `golang.org/x/term` for no-echo prompt; `github.com/zalando/go-keyring` for Credential Manager / Keychain / libsecret |
