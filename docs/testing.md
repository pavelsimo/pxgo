# Testing

Run the standard suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run static checks:

```bash
go vet ./...
```

The test suite covers:

- CLI actions and self-test
- config parsing, saving, dotenv, environment precedence
- debug logging
- Kerberos command orchestration and concurrent renewal checks
- PAC loading and PAC helper functions
- HTTP forwarding and HTTPS `CONNECT`
- SOCKS and PAC upstream modes
- upstream proxy auth and local client auth
- large data transfers and concurrent request behavior
- system proxy parsing and Windows startup command construction

Before considering the rewrite complete, run:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

