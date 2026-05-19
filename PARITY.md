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

### ✓ Request Body Buffering (large uploads) — RESOLVED

Python streams request bodies via h11 in 64 KB chunks (`handler.py:136, 531, 564`) and never fully buffers them in memory.

Go no longer reads the full request body into a byte slice. `handleHTTP` wraps incoming bodies in a replayable body store: up to 1 MiB stays in memory, and larger uploads spill to a temporary file. Each upstream proxy fallback or 407 authentication retry reopens the stored body, so large uploads remain bounded in heap while preserving Go's need for a re-readable request body.

Covered by `TestReplayableBodySpillsLargeBodiesToTempFile` plus the large transfer proxy tests.

---

### ✓ System Proxy Reload — RESOLVED

Python's `proxyreload` interval re-reads Windows Internet Options and system proxy settings every N seconds — useful when a VPN connects or disconnects.

Go's reload loop now rebuilds `wproxy` for Windows system proxy modes (`ModeAuto`, `ModePAC`, and `ModeManual`) after the configured `proxyreload` interval. Explicit config proxies, environment proxies, and local PAC files remain intentionally stable; HTTP(S) PAC URLs are reloaded.

Covered by `TestProxyReloadableModes`.

---

## Moderate Gaps

No known moderate gaps remain.

---

## Minor Gaps

No known minor gaps remain.

---

## Resolved Moderate Gaps

### ✓ Kerberos: Interactive Password Prompting — RESOLVED

Python runs `kinit` via a PTY so it can respond to the password prompt interactively (`kerberos.py:137-142`, `fcntl.ioctl TIOCSCTTY`). The password is re-fetched from the keyring on each `kinit` attempt.

Go now runs password-based `kinit` on Unix-like platforms through a pseudo-terminal using `github.com/creack/pty`, so interactive-only `kinit` variants see a controlling TTY. The password callback re-checks the keyring on each attempt before falling back to the startup password. Windows continues to rely on SSPI rather than `kinit`.

Covered by `TestDefaultKinitPasswordRunnerUsesPTY` and `TestKerberosPasswordFuncRefetchesKeyring`.

---

### ✓ Quit Robustness + Security — RESOLVED

Python retries the quit request up to 5 times with polling and waits for the socket to fully close before confirming success (`config.py:240-312`). The `/PxQuit` handler validates the client IP against the allow list.

Go now checks the allow rules before honoring `/PxgoQuit`. The CLI `--quit` path first verifies that the proxy is running, retries the quit request, and waits for the listening socket to close before reporting success.

Covered by `TestQuitEndpointRequiresAllowedClient`, `TestQuitEndpointStopsProxy`, and `TestCLIQuitStopsRunningProxy`.

---

### ✓ Crash Recovery / Traceback Logging — RESOLVED

Python installs a `sys.excepthook` that captures unhandled exceptions and writes a traceback to `debug.log` in the working directory even when logging is disabled (`main.py:318-331`).

Go now logs recovered proxy-handler panics and top-level panics through `debug.LogPanic`. When debug logging is disabled, panic traces are written to the working-directory log path (`debug-main.log`), matching pxgo's existing log naming.

Covered by `TestLogPanicWritesFileWithoutDebug`.

---

### ✓ `--test` Method Coverage for Single URL — NOT A GAP

Python single-URL `--test=URL` runs a single GET. Python's five-method sweep is only used for `--test=all` / `--test=all:base`.

Go matches that behavior: it tests only GET for a single `--test=URL`, and exercises GET, POST, PUT, DELETE, and PATCH in all-mode.

---

### ✓ Silent `--save` and `--password` — RESOLVED

Python prints a confirmation and echoes the written config to stdout after `--save` (`config.py:672-683`), and prints prompts and success messages for `--password`.

Go now prints a save confirmation and echoes the written config after `--save`. `--password` and `--client-password` already print success messages.

---

## Intentional Differences

### ✓ workers / threads / foreground — INTENTIONAL COMPATIBILITY SETTINGS

Python's `workers=N` spawns N−1 child processes (`main.py:166-182`), each running a full asyncio event loop. `threads=N` sets the `ThreadPoolExecutor` size per process. `foreground=0` detaches the console on Windows for compiled/pythonw background launches.

Go parses, stores, and round-trips these settings for config compatibility, but it does not use Python's process/thread pool model. pxgo uses one goroutine per connection and Go's runtime scheduler for concurrency, so `workers` and `threads` would add operational complexity without improving feature parity. The Go binary runs as a normal foreground console process unless launched by the user's service/startup manager; Windows startup install remains covered separately.

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
| Kerberos ticket lifecycle | Same check/renewal/retry intervals; Heimdal and MIT detection; Unix password `kinit` runs through a PTY |
| Proxy reload for PAC/system proxy | HTTP(S) PAC sources and Windows system proxy settings reloaded on `proxyreload` interval |
| CONNECT tunneling | Idle timeout, bidirectional relay |
| Log levels 0-4 | `--verbose`, `--debug`, `--uniqlog`, `--log=N`, `PXGO_LOG=`, `settings:log=` |
| dotenv loading | CWD then script dir; same precedence |
| Windows startup install | Registry key, `--force` flag, `--uninstall` |
| Config INI save/load | All keys round-trip correctly |
| Quit / restart | Functionally equivalent, including allow validation and shutdown polling |
| Windows SSPI | Transparent SSO via `github.com/alexbrainman/sspi`; NTLM/Negotiate without explicit credentials |
| OS keyring + interactive password | `golang.org/x/term` for no-echo prompt; `github.com/zalando/go-keyring` for Credential Manager / Keychain / libsecret |
