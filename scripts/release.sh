#!/bin/sh
set -e
VERSION=${VERSION:-$(git describe --tags --dirty --always 2>/dev/null || echo dev)}
go build -ldflags "-X main.version=$VERSION" -o finch ./cmd/finch
