# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pxgo .

FROM alpine:latest AS runtime

RUN apk add --no-cache ca-certificates krb5 tini

WORKDIR /pxgo
COPY --from=builder /out/pxgo /usr/local/bin/pxgo
COPY pxgo.ini /pxgo/pxgo.ini
COPY docker/start.sh /pxgo/start.sh

EXPOSE 3128
ENTRYPOINT ["tini", "--", "/bin/sh", "/pxgo/start.sh"]
