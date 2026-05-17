# Configuration

pxgo configuration sources are applied in this order:

```text
defaults < pxgo.ini < .env < environment < command line
```

Environment variables use the `PXGO_` prefix. For example, `--proxy` maps to
`PXGO_PROXY`, and `--client-username` maps to `PXGO_CLIENT_USERNAME`.

## Config File Lookup

When `--config` is provided, pxgo reads that exact file.

Without `--config`, pxgo checks:

1. `./pxgo.ini`
2. the platform config directory
3. `pxgo.ini` next to the executable

Platform config directories:

- Windows: `%APPDATA%\pxgo`
- macOS: `~/Library/Application Support/pxgo`
- Linux/Unix: `$XDG_CONFIG_HOME/pxgo` or `~/.config/pxgo`

## Starter Config

Generate a config:

```bash
./pxgo --save --config=./pxgo.ini --proxy=proxy.company.com:8080
```

Use the commented repository sample [../pxgo.ini](../pxgo.ini) when you want a
human-edited config with explanations.

## Proxy Section

| Key / Flag | Default | Description |
| --- | --- | --- |
| `server`, `proxy` / `--proxy` | empty | Upstream proxy server list |
| `pac` / `--pac` | empty | PAC URL or local file |
| `pac_encoding` / `--pac-encoding` | `utf-8` | PAC file encoding |
| `port` / `--port` | `3128` | Local listen port |
| `listen` / `--listen` | `127.0.0.1` | Local listen address list |
| `gateway` / `--gateway` | `0` | Bind all interfaces |
| `hostonly` / `--hostonly` | `0` | Bind all interfaces but allow local host IPs |
| `allow` / `--allow` | `*.*.*.*` | Client allow list |
| `noproxy` / `--noproxy` | empty | Direct-connect bypass list |
| `useragent` / `--useragent` | empty | Override or set `User-Agent` |
| `username` / `--username` | empty | Upstream auth username or Kerberos principal |
| `auth` / `--auth` | empty | Upstream auth selector |
| `kerberos` / `--kerberos` | `0` | Enable Kerberos ticket management |

## Client Section

| Key / Flag | Default | Description |
| --- | --- | --- |
| `client_auth` / `--client-auth` | `NONE` | Local client auth selector |
| `client_username` / `--client-username` | empty | Local client auth username |
| `client_nosspi` / `--client-nosspi` | `0` | Compatibility flag retained from Python Px |

## Settings Section

| Key / Flag | Default | Description |
| --- | --- | --- |
| `workers` / `--workers` | `1` | Compatibility setting retained for config parity |
| `threads` / `--threads` | `32` | Compatibility setting retained for config parity |
| `idle` / `--idle` | `30` | CONNECT tunnel idle timeout in seconds |
| `socktimeout` / `--socktimeout` | `20.0` | Upstream socket timeout in seconds |
| `proxyreload` / `--proxyreload` | `60` | PAC/system proxy refresh interval |
| `foreground` / `--foreground` | `0` | Compatibility flag |
| `log` / `--log` | `0` | Debug log destination: `1`=script dir, `2`=cwd, `3`=unique file, `4`=stdout |

## Passwords

Store credentials interactively (prompts with no echo, saves to OS keyring):

```bash
./pxgo --username='DOMAIN\user' --password
./pxgo --client-username=client --client-password
```

On Windows this uses Credential Manager; on macOS, Keychain; on Linux,
libsecret. Once stored, pxgo loads the password automatically when the
matching username is supplied.

For non-interactive runs (Docker, CI), use environment variables instead:

```bash
PXGO_PASSWORD='upstream-secret' ./pxgo --username='DOMAIN\user'
PXGO_CLIENT_PASSWORD='client-secret' ./pxgo --client-username=client
```

For environments without an OS keyring, opt in to plaintext storage:

```bash
PXGO_KEYRING_PLAINTEXT=1 ./pxgo --username='DOMAIN\user' --password=secret
PXGO_KEYRING_PLAINTEXT=1 ./pxgo --client-username=client --client-password=secret
```

Use `PXGO_KEYRING_FILE=/path/to/keyring.json` to choose the plaintext keyring
file.
