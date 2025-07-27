
GOLANGCI_LINT = golangci-lint
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

.PHONY: test lint build docker-build


test:
	go test ./...

lint:
	$(GOLANGCI_LINT) run ./...

build:
	go build -ldflags "-X main.version=$(VERSION)" -o finch ./cmd/finch

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t finch:$(VERSION) .
