# pxgo Documentation

pxgo is a single-binary HTTP/HTTPS proxy for developer machines, build agents,
and local services that need to authenticate through corporate upstream proxies.

By default pxgo listens on `127.0.0.1:3128` and can be configured with CLI
flags, environment variables, `.env`, or `pxgo.ini`.

## Try it

Build and run pxgo from this repository:

```bash
make build
./bin/pxgo
```

Point your browser, package manager, or CLI at the local proxy:

```text
HTTP proxy:  127.0.0.1:3128
HTTPS proxy: 127.0.0.1:3128
```

Add an upstream proxy or PAC file when your network needs one:

```bash
pxgo --proxy=proxy.company.com:8080
pxgo --pac=http://proxy.company.com/proxy.pac
```

## Pick your path

- [Installation](installation.md)
- [Usage](usage.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
- [Build](build.md)
- [Testing](testing.md)
- [Benchmarking](benchmarking.md)

## What pxgo handles

- **Upstream authentication.** Select `ANY`, `ANYSAFE`, `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC`, or pass-through modes.
- **Kerberos workflows.** Create and refresh per-process credential caches using host Kerberos tooling.
- **PAC and bypass rules.** Load PAC files and bypass upstream proxies for local hosts, domains, CIDR ranges, IP ranges, and wildcard IPv4 globs.
- **Remote access controls.** Keep the default loopback-only listener or opt in to gateway and host-only modes.
