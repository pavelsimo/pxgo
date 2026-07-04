# Benchmarking

Two layers: Go micro-benchmarks for the proxy hot paths, and an end-to-end
load comparison against Python px. Re-run both after any performance change
and update the baselines below.

## Micro-benchmarks

```bash
make bench
```

Runs `BenchmarkHTTPProxy` (plain-HTTP forwarding) and `BenchmarkCONNECTProxy`
(HTTPS tunneling) five times with allocation stats. Compare runs with
[benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat):

```bash
go test -bench 'HTTPProxy|CONNECTProxy' -benchmem -count 10 -run '^$' ./internal/proxy > new.txt
benchstat old.txt new.txt
```

Repeated back-to-back runs on one machine accumulate sockets in TIME_WAIT and
can produce entire runs at ~1 ms/op; discard those outliers (or wait between
runs) and read the steady-state numbers.

### Baseline

Linux amd64, AMD Ryzen 7 9850X3D (16 threads), Go 1.25, 2026-07-04, steady state:

| Benchmark | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| BenchmarkHTTPProxy-16 | ~34,000 | ~50,000 | ~188 |
| BenchmarkCONNECTProxy-16 | ~50,000 | ~45,000 | ~300 |

## End-to-end comparison vs Python px

```bash
make build
scripts/bench-e2e.sh
```

Prerequisites: `hey`, `iperf3`, `proxytunnel`, `python3`, and
`px` (`pip install px-proxy`). The script runs identical load through pxgo and
px on the same machine: 1 KB and 10 MB plain-HTTP fetches (RPS, p50/p99
latency via hey) and an iperf3 session tunneled over CONNECT (MB/s), plus
peak RSS for each proxy.

Record results here after running:

| Proxy | Scenario | RPS | p50 | p99 | MB/s | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- |
| pxgo | HTTP 1 KB | _run `scripts/bench-e2e.sh`_ | | | — | |
| px | HTTP 1 KB | | | | — | |
| pxgo | HTTP 10 MB | | | | — | |
| px | HTTP 10 MB | | | | — | |
| pxgo | CONNECT iperf3 | — | — | — | | |
| px | CONNECT iperf3 | — | — | — | | |
