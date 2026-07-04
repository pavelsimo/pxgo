#!/usr/bin/env bash
# bench-e2e.sh — run identical load through pxgo and Python px on the same box.
#
# Measures plain-HTTP RPS/latency (hey) and CONNECT tunnel throughput (iperf3)
# for both proxies against a local origin, so the numbers are comparable.
# Record the results in docs/benchmarking.md.
#
# Prereqs: hey, iperf3, proxytunnel, python3, px (pip install px-proxy),
# and ./bin/pxgo (make build).
set -euo pipefail

PXGO_BIN=${PXGO_BIN:-./bin/pxgo}
PXGO_PORT=${PXGO_PORT:-3128}
PX_PORT=${PX_PORT:-3129}
ORIGIN_PORT=${ORIGIN_PORT:-8000}
IPERF_PORT=${IPERF_PORT:-5201}
REQUESTS=${REQUESTS:-5000}
CONCURRENCY=${CONCURRENCY:-100}

for tool in hey iperf3 proxytunnel python3 px "$PXGO_BIN"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing prerequisite: $tool" >&2; exit 1; }
done

cleanup() {
  # shellcheck disable=SC2046
  kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

# 1. Local origin serving a 1 KB and a 10 MB blob.
ORIGIN_DIR=$(mktemp -d)
head -c 1024 /dev/urandom >"$ORIGIN_DIR/1k.bin"
head -c $((10 * 1024 * 1024)) /dev/urandom >"$ORIGIN_DIR/10m.bin"
python3 -m http.server "$ORIGIN_PORT" --directory "$ORIGIN_DIR" >/dev/null 2>&1 &

# 2. Start both proxies with equivalent config.
"$PXGO_BIN" --port="$PXGO_PORT" &
px --port="$PX_PORT" &
sleep 1

run_http() {
  local name=$1 port=$2 blob=$3
  echo "=== HTTP ${blob} via ${name} (127.0.0.1:${port}) ==="
  hey -n "$REQUESTS" -c "$CONCURRENCY" -x "http://127.0.0.1:${port}" \
    "http://127.0.0.1:${ORIGIN_PORT}/${blob}"
}

# 3. Plain-HTTP throughput + latency through each proxy.
run_http pxgo "$PXGO_PORT" 1k.bin
run_http px "$PX_PORT" 1k.bin
run_http pxgo "$PXGO_PORT" 10m.bin
run_http px "$PX_PORT" 10m.bin

# 4. CONNECT tunnel throughput (iperf3 tunneled via each proxy).
iperf3 -s -p "$IPERF_PORT" -D
run_tunnel() {
  local name=$1 proxy_port=$2 local_port=$3
  echo "=== CONNECT tunnel via ${name} ==="
  proxytunnel -p "127.0.0.1:${proxy_port}" -d "127.0.0.1:${IPERF_PORT}" -a "$local_port" &
  sleep 0.5
  iperf3 -c 127.0.0.1 -p "$local_port"
}
run_tunnel pxgo "$PXGO_PORT" 15201
run_tunnel px "$PX_PORT" 15202

# 5. Peak RSS per proxy.
echo "=== peak RSS (KB) ==="
ps -o rss=,comm= -C pxgo,px 2>/dev/null || true
