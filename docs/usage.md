# Usage

## Basic Proxy

Start pxgo:

```bash
./pxgo
```

Configure applications to use `127.0.0.1:3128` as their HTTP and HTTPS proxy.

## Upstream Proxy

```bash
./pxgo --proxy=proxy.company.com:8080
```

Multiple upstream proxies can be comma-separated:

```bash
./pxgo --proxy=proxy-a.company.com:8080,proxy-b.company.com:8080
```

pxgo tries the returned proxy list in order and falls back when a proxy fails.

## PAC File

```bash
./pxgo --pac=http://proxy.company.com/proxy.pac
./pxgo --pac=/path/to/proxy.pac
```

For non-UTF-8 PAC files:

```bash
./pxgo --pac=/path/to/proxy.pac --pac-encoding=latin1
```

## Bypass Rules

`--noproxy` skips the upstream proxy for matching destinations:

```bash
./pxgo --proxy=proxy.company.com:8080 --noproxy=localhost,example.com,10.0.*.*
```

Supported values include exact IPs, wildcard IPv4 globs, IPv4 ranges, CIDR
ranges, and host/domain suffixes.

## Upstream Authentication

Set `--auth` to select upstream proxy authentication:

```bash
PX_PASSWORD='secret' ./pxgo \
  --proxy=proxy.company.com:8080 \
  --auth=NTLM \
  --username='DOMAIN\user'
```

Supported auth selectors:

- `ANY`: try `NEGOTIATE`, `NTLM`, `DIGEST`, then `BASIC`
- `ANYSAFE`: try `NEGOTIATE`, `NTLM`, then `DIGEST`
- `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC`: force one mode
- `NONE`: pass proxy authentication through from the client
- `ONLYNTLM`, `NOBASIC`, `SAFENONTLM`: selector forms matching the Python Px convention

## Kerberos

Kerberos ticket management is available on Linux and macOS:

```bash
PX_PASSWORD='secret' ./pxgo --kerberos --username=user@REALM
```

pxgo creates a per-process credential cache, runs `kinit`, refreshes tickets with
`kinit -R` when possible, and removes the cache on exit. The host still needs
working Kerberos configuration such as `/etc/krb5.conf`.

## Client Authentication

By default local clients can use pxgo without authenticating. Require client auth:

```bash
PX_CLIENT_PASSWORD='client-secret' ./pxgo \
  --client-auth=DIGEST \
  --client-username=client
```

Supported client auth modes are `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC`, `ANY`,
`ANYSAFE`, and `NONE`.

## Remote Clients

Default mode listens only on `127.0.0.1`.

Allow remote clients:

```bash
./pxgo --gateway --allow=192.168.1.*
```

Allow only IP addresses assigned to local interfaces:

```bash
./pxgo --hostonly
```

## Logging

```bash
./pxgo --verbose
./pxgo --debug
./pxgo --uniqlog
```

`--verbose` logs to stdout. `--debug` and `--uniqlog` write debug logs to files.

## Self-Test

```bash
./pxgo --test
./pxgo --test=https://example.com
./pxgo --test=all:https://httpbin.org
```

`all` mode checks several HTTP methods through the proxy.
