# TODO — Bugs, Performance, Parity, Architecture & Docs

Audit of all non-test source (~4k lines) with a focus on making the proxy **fast**
while keeping full feature parity with [genotrance/px](https://github.com/genotrance/px).
The hot path is `ServeHTTP` (`internal/proxy/proxy.go`) → PAC/wproxy lookup
(`internal/pac/pac.go`, `internal/wproxy/wproxy.go`) → upstream dial/round-trip →
CONNECT relay. Performance items are ordered by expected gain.

**Status legend:** ✅ implemented in the current working tree (uncommitted) ·
❌ still open. Line numbers on ✅ items refer to the pre-fix code and are kept
for history; open items have refreshed references.

---

## Performance

### P1. New `http.Transport` created per request — no upstream connection reuse (`internal/proxy/proxy.go:1080`, `internal/proxy/proxy.go:1116`)

**Status: ✅ implemented (uncommitted)** — `Server.transports sync.Map` +
`httpTransportForProxy` (`proxy.go:1185`); cleared on `Shutdown` and on proxy
reload. See P12 for a follow-up on the eviction policy.

**Why?** `roundTripHTTPWithProxyFallback` calls `s.httpTransportForProxy(candidate)`
for **every** plain-HTTP request, so every request pays a fresh TCP handshake (plus
proxy handshake) to the upstream — HTTP keep-alive is never used. This is the single
biggest latency/throughput loss in the HTTP path: for a request to the same upstream
you pay ~1 RTT of connect time that keep-alive would eliminate entirely, and under load
you also burn ephemeral ports.

It's also a resource leak: a zero-value `http.Transport` has `IdleConnTimeout = 0`
(never expire). Each abandoned transport can keep its idle keep-alive connection open
until the peer closes it, so file descriptors pile up under load.

**Proposed solution:** Cache transports on `Server`, keyed by the proxy candidate
(`DIRECT` or `scheme://host:port`). Create once, reuse forever, and configure sane
pool limits.

```go
// Server gains a transport cache:
type Server struct {
    // ...existing fields...
    transports sync.Map // key string -> *http.Transport
}

func (s *Server) httpTransportForProxy(p wproxy.Server) *http.Transport {
    key := "direct"
    if p != wproxy.Direct {
        key = proxyScheme(p) + "://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
    }
    if t, ok := s.transports.Load(key); ok {
        return t.(*http.Transport)
    }
    timeout := time.Duration(s.cfg.SockTimeout * float64(time.Second))
    transport := &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   timeout,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        ResponseHeaderTimeout: timeout,
        MaxIdleConns:          100,
        MaxIdleConnsPerHost:   32,
        IdleConnTimeout:       90 * time.Second,
    }
    if p != wproxy.Direct {
        scheme := proxyScheme(p)
        addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
        if strings.HasPrefix(scheme, "socks") {
            transport.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
                return dialSOCKSProxy(ctx, scheme, addr, target, timeout)
            }
        } else {
            transport.Proxy = http.ProxyURL(&url.URL{Scheme: scheme, Host: addr})
        }
    }
    actual, _ := s.transports.LoadOrStore(key, transport)
    return actual.(*http.Transport)
}
```

Also call `CloseIdleConnections()` on all cached transports in `Shutdown`, and clear
the cache in `reloadProxyIfDue` when the proxy set changes. **Note:** this interacts
with B4 (NTLM connection pinning) — see below before implementing.

---

### P2. PAC evaluation fully serialized behind one mutex and one goja VM (`internal/pac/pac.go:20-26`, `internal/pac/pac.go:99`)

**Status: ✅ implemented (uncommitted)** — compiled `*goja.Program` + per-runtime
`sync.Pool` of VMs (`pacRuntime` in `pac.go`); evaluation is lock-free.

**Why?** Every request — HTTP *and* CONNECT — runs `Pac.FindProxyForURL`, which takes
`p.mu` around a single shared `goja.Runtime`. With N concurrent clients, N−1 of them
queue on the mutex while one executes JavaScript. Worse, PAC files commonly call
`dnsResolve()`, which does a blocking OS DNS lookup **while holding the lock** — one
slow resolve stalls the entire proxy. This caps the proxy at single-threaded PAC
throughput no matter how many cores you have.

**Proposed solution:** Compile the PAC script once to a `*goja.Program`, then keep a
`sync.Pool` of VMs that each ran the compiled program. Requests grab a VM, evaluate,
and put it back — fully parallel evaluation.

```go
type Pac struct {
    location string
    encoding string

    mu      sync.Mutex   // guards (re)load only, not evaluation
    program *goja.Program
    vmPool  sync.Pool    // of *pacVM
}

type pacVM struct {
    vm *goja.Runtime
    fn goja.Callable
}

func (p *Pac) compileLocked(text string) error {
    prog, err := goja.Compile("pac.js", pacUtils+"\n"+text, false)
    if err != nil {
        return err
    }
    p.program = prog
    p.vmPool = sync.Pool{New: func() any { return p.newVM() }}
    return nil
}

func (p *Pac) newVM() *pacVM {
    vm := goja.New()
    _ = vm.Set("dnsResolve", p.DNSResolve)
    _ = vm.Set("myIpAddress", p.MyIPAddress)
    _ = vm.Set("alert", func(string) {})
    if _, err := vm.RunProgram(p.program); err != nil {
        return nil
    }
    fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
    if !ok {
        return nil
    }
    return &pacVM{vm: vm, fn: fn}
}

func (p *Pac) FindProxyForURL(rawurl, host string) string {
    p.ensureLoaded() // takes p.mu only if program == nil
    v, _ := p.vmPool.Get().(*pacVM)
    if v == nil {
        return directProxy
    }
    defer p.vmPool.Put(v)
    out, err := v.fn(goja.Undefined(), v.vm.ToValue(rawurl), v.vm.ToValue(host))
    if err != nil {
        return directProxy
    }
    return normalizePACResult(out.String()) // see P10
}
```

Additionally cache `dnsResolve` results with a short TTL (see P5 — reuse the same
cache) so PAC files that resolve the same hosts repeatedly don't hammer DNS.

---

### P3. Failed PAC load is retried on every request with an HTTP GET that has **no timeout**, while holding the PAC mutex (`internal/pac/pac.go:48-97`)

**Status: ✅ implemented (uncommitted)** — `pacHTTPTimeout` (10 s) on the fetch
client, `pacRetryInterval` (30 s) backoff in `ensureLoaded`.

**Why?** `loadLocked` runs on every `FindProxyForURL` while `p.fn == nil`. If the PAC
URL is unreachable or slow, **every single request** synchronously re-downloads the PAC
file — serially, because the mutex is held. And `readPACData` uses `http.Client{}` with
no timeout: a black-holed PAC server blocks a request **forever**, and since the lock is
held, it blocks *all* traffic through the proxy. This is both a performance cliff and a
de-facto deadlock bug.

**Proposed solution:** Add a client timeout and negative-result caching with backoff.

```go
type Pac struct {
    // ...
    lastLoadAttempt time.Time
}

const pacRetryInterval = 30 * time.Second

func (p *Pac) loadLocked() {
    if p.program != nil {
        return
    }
    if time.Since(p.lastLoadAttempt) < pacRetryInterval {
        return // don't hammer a broken PAC source on every request
    }
    p.lastLoadAttempt = time.Now()
    // ...existing load logic...
}

func (p *Pac) readPACData() ([]byte, error) {
    if isHTTPURL(p.location) {
        client := http.Client{Timeout: 10 * time.Second} // was: http.Client{}
        // ...
    }
    return os.ReadFile(p.location)
}
```

---

### P4. Every HTTP request body is fully buffered — up to 1 MB in RAM, then spilled to a temp file on disk (`internal/proxy/proxy.go:1051`, `internal/proxy/proxy.go:1222-1261`)

**Status: ✅ implemented (uncommitted)** — `mayRetryUpstreamAuth` gates
`newReplayableBody`; DIRECT/no-auth requests stream the body through.

**Why?** `handleHTTP` calls `newReplayableBody(req.Body)` unconditionally so the body
can be replayed on a 407 auth retry. But that means **every** upload is read to
completion before the first upstream byte is sent (no streaming — time-to-first-byte
balloons for large uploads), and anything over 1 MB does a full write-to-disk +
read-from-disk round trip through `os.CreateTemp`. If you never need an auth retry
(no upstream auth configured, or DIRECT connection), this is pure waste: doubled
memory traffic, disk I/O, and latency on the hottest data path.

**Proposed solution:** Only make the body replayable when a retry is actually possible;
otherwise stream `req.Body` straight through.

```go
func (s *Server) handleHTTP(rw http.ResponseWriter, req *http.Request) {
    // ...
    needsReplay := s.mayRetryUpstreamAuth(proxies)
    var body *replayableBody
    if needsReplay {
        body, err = newReplayableBody(req.Body)
        if err != nil { /* 400 */ }
        defer body.Close()
    }
    // ...
}

// mayRetryUpstreamAuth reports whether any candidate is an upstream proxy that
// could answer 407 (only then do we retry and need to replay the body).
func (s *Server) mayRetryUpstreamAuth(proxies []wproxy.Server) bool {
    if len(upstreamAuthModes(s.cfg.Auth)) == 0 && s.cfg.Auth != "" {
        return false // auth=NONE: we never retry
    }
    for _, p := range proxyCandidates(proxies) {
        if p != wproxy.Direct {
            return true
        }
    }
    return false
}

// newOutboundRequest streams when body == nil:
func (s *Server) newOutboundRequest(req *http.Request, u *url.URL, body *replayableBody, proxyAuth string) (*http.Request, error) {
    outReq := req.Clone(req.Context())
    outReq.URL = u
    outReq.RequestURI = ""
    if body != nil {
        rc, err := body.Open()
        if err != nil {
            return nil, err
        }
        outReq.Body = rc
        outReq.ContentLength = body.Size()
    } // else: keep req.Body as-is — fully streamed
    // ...
}
```

(When streaming, proxy fallback for a *failed connect* still works because
`http.Transport` returns before consuming the body on connection errors; only
mid-body failures can't fall back — same trade-off every streaming proxy makes.)

---

### P5. Blocking, uncached DNS lookup on the hot path for noproxy matching (`internal/wproxy/wproxy.go:398-419`)

**Status: ✅ implemented (uncommitted)** — new `internal/dnscache` package
(60 s hit TTL, 5 s negative TTL, 4096-entry cap), shared by `wproxy` noproxy
matching and PAC `dnsResolve()`. Remember to document it (see D2).

**Why?** When `--noproxy` contains any IP rule and the request target is a hostname,
`isNoProxy` calls `net.LookupIP(host)` synchronously on **every request**. A typical
resolver round trip is 1–50 ms — often more than the entire proxied request should
take — and a slow/broken resolver adds seconds. There is no caching whatsoever, so
100 requests to the same host do 100 identical lookups.

**Proposed solution:** A tiny TTL cache in front of `LookupIP`.

```go
type dnsCache struct {
    mu  sync.RWMutex
    m   map[string]dnsEntry
}

type dnsEntry struct {
    ips     []net.IP
    expires time.Time
}

var lookupCache = dnsCache{m: map[string]dnsEntry{}}

func (c *dnsCache) lookup(host string) []net.IP {
    c.mu.RLock()
    e, ok := c.m[host]
    c.mu.RUnlock()
    if ok && time.Now().Before(e.expires) {
        return e.ips
    }
    ips, err := net.LookupIP(host)
    if err != nil {
        ips = nil
    }
    c.mu.Lock()
    c.m[host] = dnsEntry{ips: ips, expires: time.Now().Add(60 * time.Second)}
    c.mu.Unlock()
    return ips
}

// in isNoProxy:
ips := lookupCache.lookup(host) // was: net.LookupIP(host)
```

Share the same cache with `Pac.DNSResolve` (P2) so PAC `dnsResolve()` calls benefit
too. Add a size cap (e.g. evict when > 4096 entries) to bound memory.

---

### P6. `activityReader` defeats kernel `splice()` zero-copy in CONNECT tunnels (`internal/proxy/proxy.go:1866-1943`)

**Status: ✅ implemented (uncommitted)** — `activityReader` deleted; relay uses
read-deadline idle detection so `io.Copy` keeps the splice fast path.

**Why?** CONNECT tunnels carry virtually all HTTPS traffic — i.e. most of the bytes
this proxy will ever move. `io.Copy` between two `*net.TCPConn`s uses `splice(2)` on
Linux, moving data kernel-to-kernel with zero copies to userspace. But because the
default `idle=30` makes `copyWithActivity` wrap the source in `activityReader`, the
type assertion inside `io.Copy` fails and every byte is pumped through a 32 KB
userspace buffer instead: 2 extra copies + 2 extra syscalls per chunk, for every chunk
of every tunnel. Dropping the wrapper restores line-rate relaying.

**Proposed solution:** Implement idle detection with read deadlines instead of a
wrapper, keeping both ends as raw `*net.TCPConn` so `io.Copy` can splice.

```go
func relay(a, b net.Conn, idle time.Duration) {
    var wg sync.WaitGroup
    wg.Add(2)
    cp := func(dst, src net.Conn) {
        defer wg.Done()
        if idle <= 0 {
            _, _ = io.Copy(dst, src) // pure splice path
        } else {
            copyWithIdleDeadline(dst, src, idle)
        }
        halfClose(dst) // see B3
    }
    go cp(a, b)
    go cp(b, a)
    wg.Wait()
    _ = a.Close()
    _ = b.Close()
}

// copyWithIdleDeadline still lets io.Copy splice: src stays a raw net.Conn.
// The deadline bounds each io.Copy call; on timeout with no progress we stop.
func copyWithIdleDeadline(dst, src net.Conn, idle time.Duration) {
    for {
        _ = src.SetReadDeadline(time.Now().Add(idle))
        n, err := io.Copy(dst, src)
        if err == nil { // EOF
            return
        }
        var ne net.Error
        if errors.As(err, &ne) && ne.Timeout() && n > 0 {
            continue // data flowed during the window: not idle, re-arm
        }
        return // real error, or timeout with zero progress = idle
    }
}
```

(Each `io.Copy` call still splices; the deadline just interrupts it every `idle`
seconds to check for progress. If your goja/pac work lands first, benchmark this with
`iperf3` through the tunnel — the difference is easily measurable.)

---

### P7. Debug logging costs are paid even when logging is disabled; `fsync` per log line when enabled (`internal/debug/debug.go:99-137` and hot-path call sites e.g. `internal/proxy/proxy.go:1045`, `internal/proxy/proxy.go:1065`, `internal/proxy/proxy.go:1078`)

**Status: ✅ implemented (uncommitted)** — `debug.Dprintf`/`debug.Enabled` for
lazy formatting; per-line `Sync()` removed (panic path still syncs explicitly).

**Why?** Two separate problems:

1. Call sites build the message eagerly: `debug.Dprint(fmt.Sprintf("HTTP proxies: %v", proxies))`
   runs `fmt.Sprintf` (allocations, reflection for `%v`) on **every request** even when
   `instance == nil` and the string is thrown away. There are several of these per request.
2. When logging *is* enabled, `Debug.Write` calls `d.file.Sync()` — an `fsync(2)` —
   after **every line**, under a global mutex, and `Print` walks the stack 3 frames with
   `runtime.Caller`. Enabling `--debug` turns the proxy into an fsync benchmark.

**Proposed solution:** Cheap enabled-check + lazy formatting; drop the per-write sync.

```go
// debug.go
var enabled atomic.Bool // set true in New(), false in ResetForTest()

func Enabled() bool { return enabled.Load() }

// Dprintf formats lazily — zero cost when disabled.
func Dprintf(format string, args ...any) {
    if !enabled.Load() {
        return
    }
    instance.Print(fmt.Sprintf(format, args...))
}

func (d *Debug) Write(p []byte) (int, error) {
    d.mu.Lock()
    defer d.mu.Unlock()
    if d.file != nil {
        _, _ = d.file.Write(p) // was: Write + Sync per line
    }
    // ...
}
```

```go
// call sites, e.g. proxy.go:
debug.Dprintf("HTTP proxies: %v", proxies)   // was: debug.Dprint(fmt.Sprintf(...))
debug.Dprintf("HTTP response: %d %s", resp.StatusCode, targetURL)
```

If durability of the log file matters, sync on a 1 s ticker or on `Close()` instead
of per line.

---

### P8. Static config re-parsed on every request (`internal/proxy/proxy.go:301`, `proxy.go:327`, `proxy.go:336`, `proxy.go:454`, `proxy.go:1621`)

**Status: ✅ implemented (uncommitted)** — `clientAuthList`, `upstreamAuths`,
`allowSet`, and `hostIPs` are precomputed on `Server` in `New()`.

**Why?** Several pure functions of immutable config run per request:

- `clientAuthMethods(s.cfg.ClientAuth)` — string split/upper/trim, called 1–3× per
  request (`clientAuthEnabled`, `checkClientAuth`, `clientAuthChallenges`).
- `wproxy.ParseNoProxy(s.cfg.Allow, true)` — re-parses the whole `--allow` list into
  an `IPSet` for **every** request in `isClientAllowed` (`proxy.go:327`).
- `config.GetHostIPs()` — enumerates **all network interfaces** (syscalls) per request
  under `--hostonly` (`proxy.go:336`).
- `upstreamAuthModes(cfg.Auth)` — per auth attempt (`proxy.go:1621`).

None of these inputs change after startup. It's allocation and syscall churn on the
hottest path for zero benefit.

**Proposed solution:** Precompute in `New()` and store on `Server`.

```go
type Server struct {
    // ...existing fields...
    clientAuthList []string    // clientAuthMethods(cfg.ClientAuth), computed once
    upstreamAuths  []string    // upstreamAuthModes(cfg.Auth), computed once
    allowSet       wproxy.IPSet // ParseNoProxy(cfg.Allow, true), computed once
    hostIPs        atomic.Pointer[[]net.IP] // refreshed by background ticker
}

func New(cfg config.Config) (*Server, error) {
    // ...existing validation...
    s := &Server{ /* ... */ }
    s.clientAuthList = clientAuthMethods(cfg.ClientAuth)
    s.upstreamAuths = upstreamAuthModes(cfg.Auth)
    if cfg.Allow != "" {
        allow, _, _ := wproxy.ParseNoProxy(cfg.Allow, true)
        s.allowSet = allow
    }
    ips := config.GetHostIPs()
    s.hostIPs.Store(&ips)
    // refresh host IPs every 30s in a goroutine (interfaces can change)
    return s, nil
}

// isClientAllowed uses s.allowSet.Contains(ip) and *s.hostIPs.Load()
// instead of re-parsing / re-enumerating.
```

---

### P9. Kerberos `Check` takes a global mutex on every request — and a 30 s `kinit` subprocess can run while holding it (`internal/proxy/proxy.go:309` → `internal/kerberos/kerberos.go:128-157`)

**Status: ❌ open.** Consider implementing it as part of A2 (background
maintenance ticker), which removes the per-request call site entirely.

**Why?** `ServeHTTP` calls `s.reloadKerberos(false)` → `m.Check(false)` which acquires
`m.mu` unconditionally. Under load that's a contended global lock on every request just
to compare two timestamps. Far worse: when a refresh *is* due, `KinitWithPassword` runs
a subprocess with a 30-second timeout **inside the lock** — every request through the
proxy hangs until kinit finishes.

**Proposed solution:** Lock-free fast path + refresh in a background goroutine.

```go
type Manager struct {
    // ...
    nextCheckUnix atomic.Int64 // mirrors NextCheck for the fast path
    refreshing    atomic.Bool
}

func (m *Manager) Check(force bool) {
    if !force && time.Now().Unix() < m.nextCheckUnix.Load() {
        return // hot path: one atomic load, no mutex
    }
    if !m.refreshing.CompareAndSwap(false, true) {
        return // refresh already in flight; requests proceed with current ticket
    }
    go func() {
        defer m.refreshing.Store(false)
        m.mu.Lock()
        defer m.mu.Unlock()
        m.checkLocked(force) // existing Check body; updates NextCheck
        m.nextCheckUnix.Store(m.NextCheck.Unix())
    }()
}
```

Requests never block on ticket management; at worst one request cycle uses a ticket
that is about to be renewed (the `RenewalMargin` of 10 minutes makes that safe).

---

### P10. Minor hot-path allocations

**Status: partially done** — per-item markers below.

Small individually, but they all sit on the per-request path:

- ✅ **`replacements` map rebuilt on every PAC call** (`internal/pac/pac.go:109-120`).
  Replace with a package-level `strings.Replacer` (also fixes reliance on map
  iteration order):

  ```go
  var pacResultReplacer = strings.NewReplacer(
      "PROXY ", "", "HTTP ", "", "HTTPS ", "https://",
      "SOCKS4 ", "socks4://", "SOCKS5 ", "socks5://", "SOCKS ", "socks5://",
      ";", ",",
  )
  func normalizePACResult(s string) string { return pacResultReplacer.Replace(s) }
  ```

- ✅ **`hostMatchesNoProxy` re-normalizes every bypass entry per request** —
  resolved: entries are lowercased once at parse time and matched via the
  `NoProxyHosts` map (`internal/wproxy/wproxy.go:174`, `wproxy.go:400`).

- ❌ **`FindProxyForURL` copies the server slice per request**
  (`internal/wproxy/wproxy.go:388`): `append([]Server(nil), w.Servers...)`. Callers
  never mutate it — return `w.Servers` directly (document it as read-only).

- ❌ **klist parsing regexes recompiled per call**
  (`internal/kerberos/kerberos.go:277`, `kerberos.go:291`) — hoist
  `regexp.MustCompile` to package vars. Cold path, but free to fix.

- ❌ **`ntlmChallenge` copies the challenge on every lookup**
  (`internal/proxy/proxy.go:644-649`) — the copy is only needed by one of three
  callers; return the slice and copy at the single mutation site.

---

### P11. Proxy reload builds the new wproxy while holding the write lock — a slow PAC fetch stalls every request (`internal/proxy/proxy.go:377-407`)

**Status: ❌ open.** *(New finding — not in the original audit.)*

**Why?** `reloadProxyIfDue` takes `s.wmu.Lock()` and then calls
`buildWproxy(s.cfg)` **inside** the critical section. For PAC-URL and Windows
system-proxy modes that rebuild can do network I/O — the PAC download alone is
allowed up to `pacHTTPTimeout` (10 s). Every request path takes `wmu.RLock()`
(`findProxyForRequest`, `proxy.go:434`), so during a slow reload the entire proxy
freezes. On top of that, `clearTransports()` runs on **every** reload even when
the proxy set is unchanged, throwing away all warm keep-alive pools (undoing P1)
once per `proxyreload` interval — 60 s by default.

**Proposed solution:** Rebuild outside the lock, guard against concurrent
rebuilds with an atomic flag, swap under the lock, and only drop transports when
the routing actually changed.

```go
type Server struct {
    // ...existing fields...
    reloading atomic.Bool
}

func (s *Server) reloadProxyIfDue() error {
    // ...existing RLock'd "reloadable + due" fast path unchanged...

    if !s.reloading.CompareAndSwap(false, true) {
        return nil // rebuild already in flight; keep serving with current wproxy
    }
    defer s.reloading.Store(false)

    wp, err := buildWproxy(s.cfg) // slow: may download a PAC file — no lock held
    if err != nil {
        return err
    }

    s.wmu.Lock()
    changed := !equalServers(wp.Servers, s.w.Servers) || wp.Mode != s.w.Mode
    s.w = wp
    s.lastReload = time.Now()
    s.wmu.Unlock()

    if changed {
        s.clearTransports() // drop keep-alive pools only when routing changed
    }
    return nil
}

func equalServers(a, b []wproxy.Server) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
```

Follow-up: A2 moves this off the request path entirely (background ticker), at
which point the `reloading` flag becomes unnecessary. Note the behavior change:
today a failed reload returns 502 to the request that triggered it; after this
change (and A2) reload errors should be logged via `debug.Dprintf` and the
previous wproxy kept.

---

### P12. Transport cache eviction clears the entire cache (`internal/proxy/proxy.go:1195-1200`)

**Status: ❌ open (low severity).** *(Introduced by the P1 fix.)*

**Why?** `httpTransportForProxy` counts entries and, past `maxCachedTransports`
(64), calls `clearTransports()` — dropping every hot connection pool because one
new proxy key showed up. Hitting 64 distinct upstream proxies is rare (requires a
PAC file that fans out widely), but when it happens the proxy pays full
reconnect cost for *all* traffic, repeatedly.

**Proposed solution:** Evict a single arbitrary entry instead of everything.

```go
if size >= maxCachedTransports {
    s.transports.Range(func(k, v any) bool {
        v.(*http.Transport).CloseIdleConnections()
        s.transports.Delete(k)
        return false // evict one victim, keep the rest warm
    })
}
```

(A true LRU is overkill here; single-victim eviction bounds the map without the
stampede.)

---

### P13. No benchmark harness — "faster than px" is currently unverifiable

**Status: ❌ open.** *(New — required to validate the project's performance goal.)*

**Why?** The stated goal is to outperform genotrance/px, but the repo has no
`make bench` target, no end-to-end load-test script, and no recorded baseline.
Go benchmarks exist (`BenchmarkHTTPProxy`, `BenchmarkCONNECTProxy` in
`internal/proxy/proxy_test.go`) but nothing runs them routinely or compares
against px. Every perf item above lands blind without this.

**Proposed solution:** Two layers — micro and end-to-end.

```makefile
# Makefile
bench:
	go test -bench 'HTTPProxy|CONNECTProxy' -benchmem -count 5 ./internal/proxy
```

```bash
#!/usr/bin/env bash
# scripts/bench-e2e.sh — run identical load through pxgo and px on the same box.
# Prereqs: hey, iperf3, proxytunnel (or socat), python3, px (pip install px-proxy).
set -euo pipefail

# 1. Local origin serving a 1 KB and a 10 MB blob:
python3 -m http.server 8000 --directory "$(mktemp -d)" &

# 2. Start both proxies with equivalent config:
./pxgo --port=3128 &
px     --port=3129 &

# 3. Plain-HTTP throughput + latency through each proxy:
hey -n 5000 -c 100 -x http://127.0.0.1:3128 http://127.0.0.1:8000/1k.bin
hey -n 5000 -c 100 -x http://127.0.0.1:3129 http://127.0.0.1:8000/1k.bin

# 4. CONNECT tunnel throughput (iperf3 server on :5201, tunneled via each proxy):
iperf3 -s -D
proxytunnel -p 127.0.0.1:3128 -d 127.0.0.1:5201 -a 15201 & iperf3 -c 127.0.0.1 -p 15201
proxytunnel -p 127.0.0.1:3129 -d 127.0.0.1:5201 -a 15202 & iperf3 -c 127.0.0.1 -p 15202

# 5. Record RPS, p50/p99 latency, tunnel MB/s, and peak RSS (ps -o rss=) per proxy.
```

Check the methodology plus baseline numbers into `docs/benchmarking.md` (D3) and
re-run after each perf change. Suggested table columns: proxy, scenario, RPS,
p50, p99, MB/s, peak RSS.

---

### P14. Client-auth state behind one global mutex (`internal/proxy/proxy.go:67`, maps at `proxy.go:644-668`)

**Status: ❌ open (minor — only matters with `--client-auth` under high concurrency).**

**Why?** `clientAuth`, `ntlm`, and `ntlmSPNEGO` are three maps keyed by
`RemoteAddr` behind a single `clientMu sync.Mutex`. With client auth enabled,
every request takes this lock at least once (`isClientAuthed`), and NTLM
handshakes take it several times — a global serialization point across all
connections.

**Proposed solution:** Collapse the three maps into one `sync.Map` of
per-connection state; per-entry mutation happens on that connection's own
handshake, so contention drops to near zero.

```go
type clientState struct {
    authed     atomic.Bool
    mu         sync.Mutex // guards the NTLM handshake fields below
    ntlm       []byte
    ntlmSPNEGO bool
}

type Server struct {
    // ...
    clients sync.Map // remoteAddr string -> *clientState
}

// The existing ConnState(StateClosed) hook deletes the entry, as today.
```

---

## Bugs

### B1. CONNECT drops client bytes buffered in the hijacked `bufio.Reader` (`internal/proxy/proxy.go:1323-1334`)

**Status: ✅ implemented (uncommitted)** — buffered bytes are drained into the
upstream before the relay starts.

**Why?** After `hijacker.Hijack()`, any bytes the client sent right behind the CONNECT
request (very common: TLS clients pipeline the ClientHello) may already be sitting in
`brw.Reader`. `relay(client, upstream, ...)` reads from the **raw** conn, so those
buffered bytes are silently discarded — the TLS handshake stalls until client timeout.
Intermittent, timing-dependent, and looks like "the proxy is slow/flaky."

**Proposed solution:** Drain the reader's buffer into the upstream before relaying.

```go
client, brw, err := hijacker.Hijack()
if err != nil {
    _ = upstream.Close()
    return
}
_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
_ = brw.Flush()
// Forward any bytes the client pipelined behind the CONNECT — they are
// buffered in brw.Reader and would otherwise be lost.
if n := brw.Reader.Buffered(); n > 0 {
    peeked, _ := brw.Reader.Peek(n)
    if _, err := upstream.Write(peeked); err != nil {
        _ = upstream.Close()
        _ = client.Close()
        return
    }
    _, _ = brw.Reader.Discard(n)
}
```

### B2. Upstream CONNECT response reader can over-read and lose tunnel bytes (`internal/proxy/proxy.go:1586`)

**Status: ✅ implemented (uncommitted)** — leftover buffered bytes are returned
from the CONNECT attempt and written to the client before the relay.

**Why?** `sendUpstreamConnectAttempt` wraps the upstream conn in `bufio.NewReader`
(4 KB buffer) to parse the CONNECT response, then throws the reader away. Any bytes the
upstream sent *after* the `200` headers — a server-speaks-first banner (SMTP, SSH, FTP
via CONNECT) or an early TLS record — are stranded in the discarded buffer. Those
protocols hang forever through this proxy.

**Proposed solution:** Return the leftover buffered bytes and prepend them on the
upstream→client direction.

```go
func sendUpstreamConnectAttempt(conn net.Conn, ...) (leftover []byte, err error) {
    // ...
    reader := bufio.NewReader(conn)
    resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
    // ...existing status handling...
    if n := reader.Buffered(); n > 0 {
        leftover, _ = reader.Peek(n)
        leftover = append([]byte(nil), leftover...)
    }
    return leftover, nil
}

// handleConnect: write leftover to the client before starting relay.
if len(leftover) > 0 {
    _, _ = client.Write(leftover)
}
relay(client, upstream, idle)
```

### B3. `relay` has no TCP half-close — first EOF kills both directions (`internal/proxy/proxy.go:1891-1897`)

**Status: ✅ implemented (uncommitted)** — `CloseWrite` half-close per direction,
landed together with the P6 relay rewrite.

**Why?** When one copy direction finishes, `cp` calls `closeConns()`, closing **both**
connections. A peer that does `shutdown(SHUT_WR)` after sending its request (legal and
common) still expects to *read* the response — but the relay tears the whole tunnel
down, truncating in-flight data. Shows up as sporadic truncated downloads/responses.

**Proposed solution:** Half-close the write side of the destination when the source
hits EOF; fully close only after both directions complete (or idle fires).

```go
type closeWriter interface{ CloseWrite() error }

func halfClose(c net.Conn) {
    if cw, ok := c.(closeWriter); ok { // *net.TCPConn implements this
        _ = cw.CloseWrite()
        return
    }
    _ = c.Close() // fallback (e.g. TLS conns)
}

cp := func(dst, src net.Conn) {
    defer wg.Done()
    _, _ = copyWithIdleDeadline(dst, src, idle) // or io.Copy, see P6
    halfClose(dst) // was: closeConns() — let the other direction drain
}
```

(Combine with P6's `relay` rewrite — they touch the same function.)

### B4. NTLM/Negotiate upstream auth isn't pinned to one connection in the HTTP path (`internal/proxy/proxy.go:1147-1183`)

**Status: ✅ implemented (uncommitted)** — connection-oriented auth exchanges run
on a pinned single-connection transport (`MaxConnsPerHost = 1`).

**Why?** NTLM and Negotiate are *connection-oriented*: the challenge/response must
happen on a single TCP connection. `retryHTTPProxyAuth` re-issues the request through
`transport.RoundTrip`, trusting the pool to reuse the same connection. Today that
mostly works only because P1's per-request transport has exactly one connection —
**once P1 is fixed (shared pooled transports), the retry can land on a different
connection and the handshake breaks** with intermittent 407 loops.

**Proposed solution:** When the selected auth mode is connection-oriented, run the
whole exchange on a dedicated single-connection transport.

```go
// in retryHTTPProxyAuth, when entering an NTLM/Negotiate exchange:
if isConnectionAuth(authSchemeFromChallenge(challenge)) {
    pinned := transport.Clone()
    pinned.MaxConnsPerHost = 1
    pinned.DisableKeepAlives = false
    defer pinned.CloseIdleConnections()
    transport = pinned
}
```

### B5. IPv6 silently broken in `IPSet` (`internal/wproxy/wproxy.go:46-59`, `wproxy.go:71-87`)

**Status: ❌ open.**

**Why?** `AddCIDR` does `ipnet.IP = ip.To4()`, which is `nil` for IPv6, corrupting the
stored net; `Contains` starts with `ip = ip.To4(); if ip == nil { return false }`. Net
effect: any IPv6 entry in `--noproxy` or `--allow` never matches. For `--allow` that
means an operator who allows an IPv6 range gets **all IPv6 clients rejected** (fails
closed, but violates the config); for `--noproxy` IPv6 targets are never bypassed.

**Proposed solution:** Keep addresses in 16-byte form and use the stdlib matching.

```go
func (s *IPSet) AddCIDR(cidr string) error {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        ip := net.ParseIP(cidr)
        if ip == nil {
            return errors.New("bad ip")
        }
        bits := 128
        if ip.To4() != nil {
            bits = 32
            ip = ip.To4()
        }
        ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
    }
    s.nets = append(s.nets, ipnet)
    return nil
}

func (s IPSet) Contains(ip net.IP) bool {
    for _, n := range s.nets {
        if n.Contains(ip) { // handles v4 and v6 natively
            return true
        }
    }
    if ip4 := ip.To4(); ip4 != nil { // ranges stay v4-only
        for _, r := range s.ranges {
            if compareIP(ip4, r[0]) >= 0 && compareIP(ip4, r[1]) <= 0 {
                return true
            }
        }
    }
    return false
}
```

### B6. CONNECT to a bracketed IPv6 literal without a port builds a bad dial address (`internal/proxy/proxy.go:1440`)

**Status: ❌ open.**

**Why?** `if !strings.Contains(target, ":") { target += ":443" }` — an IPv6 literal
like `[::1]` *contains* colons, so the default port is never appended and the dial
fails with a confusing error.

**Proposed solution:** Decide using `net.SplitHostPort`.

```go
target := req.Host
if _, _, err := net.SplitHostPort(target); err != nil {
    target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
}
```

### B7. `<local>` bypass registers `127.0.0.0/24` instead of `127.0.0.0/8` (`internal/wproxy/wproxy.go:181`)

**Status: ❌ open.**

**Why?** The whole `127/8` block is loopback. Tools that bind `127.x.y.z` addresses
other than `127.0.0.x` (common for local dev, DNS stubs, containers) get routed to the
upstream proxy instead of connecting directly — usually failing.

**Proposed solution:**

```go
if bypass == "<local>" {
    hosts["localhost"] = true
    _ = set.AddCIDR("127.0.0.0/8") // was: 127.0.0.0/24
    continue
}
```

### B8. Upstream Digest auth: constant cnonce and nonce-count (`internal/proxy/proxy.go:1822-1823`)

**Status: ❌ open.**

**Why?** `nc := "00000001"; cnonce := "pxgocnonce"` — RFC 7616 requires the nonce count
to increment per request under the same server nonce, and the cnonce to be
unpredictable. Proxies that enforce nc monotonicity reject the *second* request with
the same nonce (intermittent 407s under keep-alive); the fixed cnonce also weakens the
qop=auth protection.

**Proposed solution:** Random cnonce per request, per-nonce counter.

```go
var digestNonceCounts sync.Map // server nonce -> *atomic.Uint64

func nextDigestNC(nonce string) string {
    v, _ := digestNonceCounts.LoadOrStore(nonce, new(atomic.Uint64))
    return fmt.Sprintf("%08x", v.(*atomic.Uint64).Add(1))
}

func newCnonce() string {
    var b [8]byte
    _, _ = rand.Read(b[:])
    return hex.EncodeToString(b[:])
}

// in upstreamProxyAuthHeader:
nc := nextDigestNC(nonce)  // was: "00000001"
cnonce := newCnonce()      // was: "pxgocnonce"
```

(Bound the map — evict entries older than the 120 s nonce lifetime.)

### B9. Client Digest auth nonce is replayable for 120 seconds (`internal/proxy/proxy.go:552`, `proxy.go:991`)

**Status: ❌ open.**

**Why?** `verifyDigestNonce` only checks that the nonce is fresh (≤120 s) and bound to
the client IP. Nothing tracks nonce+nc reuse, so a captured `Proxy-Authorization`
header can be replayed from the same source address for two minutes. Low severity
(local proxy, IP-bound), but cheap to close.

**Proposed solution:** Keep a small seen-set of `nonce:nc` pairs with 120 s expiry and
reject duplicates:

```go
var seenNonces sync.Map // "nonce|nc" -> time.Time (expiry)

func digestNonceReplayed(nonce, nc string) bool {
    key := nonce + "|" + nc
    _, loaded := seenNonces.LoadOrStore(key, time.Now().Add(120*time.Second))
    return loaded
}
// call from checkDigestClientAuth after verifyDigestNonce succeeds.
```

### B10. `debug.instance` is written and read without synchronization — data race (`internal/debug/debug.go:22`, `debug.go:48-57`, `debug.go:133-137`)

**Status: ✅ implemented (uncommitted)** — `atomic.Pointer[Debug]`, folded into
the P7 debug rework, with a concurrent init/print regression test.

**Why?** `debug.New` assigns the package-level `instance` while every request goroutine
reads it in `Dprint`. If logging is (re)initialized after the server starts (e.g. from
tests or a future SIGHUP handler), that's a data race — `go test -race` flags it, and a
torn read is undefined behavior.

**Proposed solution:** `atomic.Pointer`.

```go
var instance atomic.Pointer[Debug]

func Dprint(msg string) {
    if d := instance.Load(); d != nil {
        d.Print(msg)
    }
}

// New: instance.Store(d)   // ResetForTest: instance.Store(nil)
```

(Fold into the P7 rework of the debug package.)

### B11. No SIGINT/SIGTERM handling — Ctrl-C hard-kills the proxy (`main.go`)

**Status: ❌ open.** *(New finding — not in the original audit.)*

**Why?** `main.go` never installs a signal handler; the only graceful stop is the
`/PxgoQuit` endpoint. On Ctrl-C or `systemctl stop`, the process dies mid-flight:
open CONNECT tunnels get RST instead of a drained close, the listener isn't shut
down cleanly, and the debug log's final buffered writes are lost (per-line fsync
was removed in P7, so this now matters). Python px handles Ctrl-C cleanly, so
this is a small parity gap too.

**Proposed solution:** Wrap the serve loop in `signal.NotifyContext` with a
bounded shutdown.

```go
// main.go, in the serve path:
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

errc := make(chan error, 1)
go func() { errc <- s.Start() }()

select {
case err := <-errc:
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        return 1
    }
case <-ctx.Done():
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    _ = s.Shutdown(shutdownCtx)
}
return 0
```

`Shutdown` already closes transports and cleans up Kerberos; verify it also
syncs/closes the debug log (add a `debug.Instance().Close()` if not).

---

## Feature parity with genotrance/px

Parity was re-verified against px master (docs/configuration.md + changelog
through **v0.11.0**, April 2026). All flags, ini keys, env vars, auth prefixes
(`NO`/`SAFENO`/`ONLY`), user config directories, `PXGO_CONFIG`, `--install`
registry config path, keyring (+ plaintext escape hatch), test modes, and log
levels 0–4 are covered — see `PARITY.md`. px v0.11's asyncio rework, `pxw.exe`
GUI launcher, and Docker `IPC_LOCK` requirement are Python-specific and N/A to
Go (goroutines already provide the concurrency model px moved to).

### F1. Optional: px drop-in migration aids

**Status: ❌ open (nice-to-have, low priority).**

**Why?** pxgo deliberately renames the namespace (`--pac-encoding`, `PXGO_*`,
`pxgo.ini`) vs px (`--pac_encoding`, `PX_*`, `px.ini`). A user migrating an
existing px deployment has to rename flags, env vars, and the ini file even
though the keys are identical. Cheap to smooth over:

- Accept underscore spellings as CLI aliases (`--pac_encoding`,
  `--client_username`, …) — px itself uses underscores.
- On startup, if no `pxgo.ini` is found in any search location, fall back to
  `px.ini` in the same locations (read-only; `--save` still writes `pxgo.ini`).
- Optionally read `PX_*` env vars when the corresponding `PXGO_*` is unset.

```go
// config.go flag normalization before parsing:
func normalizeFlagName(name string) string {
    return strings.ReplaceAll(name, "_", "-") // --pac_encoding → --pac-encoding
}
```

Document the fallback order explicitly in `docs/configuration.md` if adopted.

---

## Architecture

### A1. Split `internal/proxy/proxy.go` (2,135 lines, ~10 concerns) into cohesive files

**Status: ❌ open.**

**Why?** One file currently holds client auth (Basic/Digest/NTLM/SPNEGO + DER
parsing), upstream auth (407 retry loop, Digest/NTLM headers, SSPI glue), the
transport cache, SOCKS4/4a/5 dialers, CONNECT handling, the relay loop, and
replayable-body buffering. Navigation, review, and merge conflicts all suffer;
every fix lands in the same 2k-line file.

**Proposed solution:** Mechanical moves within the same package — zero API or
behavior change, so it can land any time between feature work:

| New file | Moves in (representative) |
| --- | --- |
| `transport.go` | `httpTransportForProxy`, `clearTransports`, `dialSOCKSProxy` + SOCKS4/5 dialers |
| `auth_client.go` | `checkClientAuth`, digest verify, NTLM state machine, SPNEGO/DER helpers |
| `auth_upstream.go` | `retryHTTPProxyAuth`, `upstreamProxyAuthHeader`, SSPI call sites |
| `connect.go` | `handleConnect`, `sendUpstreamConnect*`, `connectWithProxyFallback` |
| `relay.go` | `relay`, `copyWithIdleDeadline`, `halfClose` |
| `body.go` | `replayableBody` and helpers |

Do it as a single commit with no logic edits so `git blame -C` stays useful, and
run `make test` before/after to prove behavior is untouched.

### A2. Move per-request maintenance (`reloadProxyIfDue`, `reloadKerberos`) to a background ticker

**Status: ❌ open.** Subsumes the remaining locking concerns of **P9** and
complements **P11**.

**Why?** `ServeHTTP` (`proxy.go:304-309`) runs proxy-reload and Kerberos checks
inline on every request: two branch+lock round trips on the hot path, and the
slow cases (PAC re-download, `kinit`) execute on a request goroutine. These are
time-based housekeeping tasks — they belong on a clock, not on the request path.

**Proposed solution:** One maintenance goroutine owned by the server lifecycle.

```go
type Server struct {
    // ...
    stopMaint chan struct{}
}

func (s *Server) Start() error {
    // ...existing listener setup...
    s.stopMaint = make(chan struct{})
    go s.maintenanceLoop()
    // ...
}

func (s *Server) maintenanceLoop() {
    t := time.NewTicker(time.Second)
    defer t.Stop()
    for {
        select {
        case <-t.C:
            if err := s.reloadProxyIfDue(); err != nil {
                debug.Dprintf("proxy reload failed, keeping previous: %v", err)
            }
            s.reloadKerberos(false)
        case <-s.stopMaint:
            return
        }
    }
}

// Shutdown: close(s.stopMaint) inside the existing sync.Once.
```

Behavior change to document: a failed reload no longer returns 502 to the
request that happened to trigger it — the previous proxy config stays active and
the error is logged. Tests that rely on request-triggered reload
(`TestProxyReloadableModes`) need to tick the loop or call the reload directly.

---

## Documentation

Kept as a checklist — each item is small; don't let these become essays.

- [ ] **D1. README**: mention Windows SSPI single-sign-on (no `--username`
  needed on domain-joined machines), keyring env vars (`PXGO_KEYRING_PLAINTEXT`,
  `PXGO_KEYRING_FILE`), and the `GET /PxgoQuit` endpoint used by `--quit`.
- [ ] **D2. `docs/architecture.md` refresh** (currently ~50 lines, predates the
  perf rework): transport cache keyed by proxy candidate, PAC compiled-program +
  VM pool, `internal/dnscache` (60 s / 5 s TTLs, 4096-entry cap, shared by
  noproxy matching and PAC `dnsResolve`), splice-friendly relay with half-close,
  and a lock map (`wmu`, `stateMu`, `clientMu` — what each guards, lock order).
- [ ] **D3. `docs/benchmarking.md` + `make bench`** — methodology and baseline
  table from P13; update the numbers after each perf change.
- [ ] **D4. Document `workers`/`threads`/`foreground` as accepted-but-inert**
  parity settings in `docs/configuration.md` and the `pxgo.ini` comments
  (currently only explained in `PARITY.md`).
- [ ] **D5. CHANGELOG entry** for the uncommitted perf/bugfix batch when it
  lands (transport reuse, PAC pool, dnscache, relay rewrite, CONNECT fixes,
  debug rework) — several are user-visible behavior improvements.

---

## Suggested order of attack

Done (uncommitted): P1–P8, B1–B4, B10, and the ✅ parts of P10. Remaining, in
order of expected value:

1. **P11** (reload out of the write lock + conditional transport clear) — the
   last remaining whole-proxy stall; pairs naturally with **A2**.
2. **B11** (graceful shutdown) — small, user-visible, protects the debug log.
3. **P13 + D3** (benchmark harness + baseline vs px) — land before further perf
   work so every change gets before/after numbers.
4. **B5–B9** — correctness batch (IPv6 IPSet, CONNECT v6 literal, `<local>`
   /8, Digest nc/cnonce, Digest replay).
5. **P9** (via A2), **P10 leftovers**, **P12**, **P14** — remaining hot-path and
   contention cleanups.
6. **A1** (proxy.go split) — any time, as a standalone no-logic commit.
7. **D1, D2, D4, D5** docs pass; **F1** only if px-migration demand shows up.

After each step: `make test` (race detector is already enabled) and an end-to-end
smoke test, e.g. `pxgo --test=all:httpbin.org`. For before/after numbers use the
P13 harness (`make bench` + `scripts/bench-e2e.sh`).
