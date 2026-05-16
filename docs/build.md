# Build

## Local Build

```bash
go build -o px .
```

Cross-compile examples:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/px-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o dist/px-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o dist/px-windows-amd64.exe .
```

## Docker Build

```bash
docker build -t px-go .
```

The root `Dockerfile` builds the Go binary in a Go builder image, then copies it
into a small Alpine runtime with CA certificates, Kerberos tools, and `tini`.

## Docker Test Images

The `docker/` directory contains Kerberos helper images:

- `docker/Dockerfile.mit-kdc`
- `docker/Dockerfile.heimdal-kdc`
- `docker/Dockerfile.heimdal-client`

These are intended for Kerberos integration testing and mirror the Python
project's test infrastructure.

## Version

The current version string is defined in `main.go`.

