# 🔀 pxgo

[![CI](https://github.com/pavelsimo/pxgo/actions/workflows/ci.yml/badge.svg)](https://github.com/pavelsimo/pxgo/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pavelsimo/pxgo)](https://github.com/pavelsimo/pxgo/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/pavelsimo/pxgo)](go.mod)
[![License](https://img.shields.io/github/license/pavelsimo/pxgo)](LICENSE)

**pxgo** is a Go rewrite of [Px](https://github.com/genotrance/px) — a single binary that runs a local HTTP/HTTPS
proxy so applications can authenticate through corporate NTLM or Kerberos proxies transparently.

By default pxgo listens on `127.0.0.1:3128`.

## Quick Start

Build and run from this repository:

```bash
make build
./bin/pxgo
```

Configure your browser, package manager, or CLI tool to use:

```text
HTTP proxy:  127.0.0.1:3128
HTTPS proxy: 127.0.0.1:3128
```

Run with an explicit upstream proxy:

```bash
pxgo --proxy=proxy.company.com:8080
```

Run with a PAC file:

```bash
pxgo --pac=http://proxy.company.com/proxy.pac
pxgo --pac=/path/to/proxy.pac
```

Run a self-test through pxgo:

```bash
pxgo --test
pxgo --test=all:https://httpbin.org
```

Stop a running instance:

```bash
pxgo --quit
```

## Configuration

pxgo accepts command-line flags, `PX_*` environment variables, `.env`, and
`pxgo.ini`. Precedence is:

```text
command line > environment > .env > pxgo.ini > defaults
```

Create a starter config:

```bash
pxgo --save --config=./pxgo.ini --proxy=proxy.company.com:8080 --port=3128
```

Then run it with:

```bash
pxgo --config=./pxgo.ini
```

The repository includes a commented sample config at [pxgo.ini](pxgo.ini).

## Common Flags

| Flag | Purpose |
| --- | --- |
| `--proxy=HOST:PORT` | Upstream proxy server, or comma-separated servers |
| `--pac=URL_OR_PATH` | PAC file URL or local file |
| `--port=NUM` | Local listen port, default `3128` |
| `--listen=IP[,IP]` | Local listen address list, default `127.0.0.1` |
| `--gateway` | Bind all interfaces for remote clients |
| `--hostonly` | Bind all interfaces but allow only local host interface IPs |
| `--allow=LIST` | Client allow list for `--gateway` mode |
| `--noproxy=LIST` | Hosts or IP ranges that bypass the upstream proxy |
| `--auth=TYPE` | Upstream auth mode: `ANY`, `ANYSAFE`, `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC`, `NONE` |
| `--username=USER` | Upstream proxy username or Kerberos principal |
| `--client-auth=TYPE` | Require local client auth: `NONE`, `ANY`, `ANYSAFE`, `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC` |
| `--verbose` | Log to stdout |

Use `pxgo --help` for the current CLI help.

## Documentation

- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Build](docs/build.md)
- [Testing](docs/testing.md)

## Docker

Build the runtime image:

```bash
docker build -t pxgo .
```

Run pxgo in Docker:

```bash
docker run --rm -p 3128:3128 pxgo --gateway --proxy=proxy.company.com:8080
```

See [docs/installation.md](docs/installation.md) and [docker/](docker/) for
more Docker details.

## Development

```bash
make tools       # install dev tools and Git hooks
make hooks       # install Git hooks only
make build       # build binary to bin/pxgo
make test        # run tests with race detector and coverage
make lint        # run golangci-lint
make fmt         # format code
make ci          # full CI gate: fmt-check + lint + test + build
make docs        # build docs site to dist/docs-site/
```
