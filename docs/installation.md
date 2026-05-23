# Installation

## Windows with WinGet

After the WinGet manifest for a release passes Microsoft validation, install
pxgo with:

```powershell
winget install pavelsimo.pxgo
```

## From Source

Requirements:

- Go 1.24 or newer
- Network access for first-time module download

Build:

```bash
go build -o pxgo .
```

Run:

```bash
./pxgo
```

Install somewhere on `PATH` if desired:

```bash
install -m 0755 pxgo ~/.local/bin/pxgo
```

## Docker

Build the default runtime image:

```bash
docker build -t pxgo .
```

Run with an upstream proxy:

```bash
docker run --rm -p 3128:3128 pxgo --gateway --proxy=proxy.company.com:8080
```

Mount a config file:

```bash
docker run --rm -p 3128:3128 \
  -v "$PWD/pxgo.ini:/pxgo/pxgo.ini:ro" \
  pxgo --config=/pxgo/pxgo.ini --gateway
```

The runtime image includes Kerberos command-line tools so `--kerberos` can use
`kinit` and `klist` when a suitable realm configuration is provided.

## Windows Startup

The Go port includes the Windows startup command builder and CLI flags:

```powershell
pxgo.exe --install --config C:\path\to\pxgo.ini
pxgo.exe --uninstall
```

Startup registry operations are Windows-only. On non-Windows platforms the
commands return an unsupported-platform error.
