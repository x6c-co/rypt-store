# rypt-store build tasks.

RQLITE_VERSION ?= 10.6.0
GOOS_ARCH      := $(shell go env GOOS)-$(shell go env GOARCH)
VERSION        ?= dev
LDFLAGS        := -s -w -X github.com/x6c-co/rypt-store/internal/version.Version=$(VERSION)

.PHONY: all build web generate test test-race vet vuln tools clean

all: build

## build: build the frontend and the single binary with the SPA embedded
build: web
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/rypt-store ./cmd/rypt-store

## web: build the React SPA into web/dist
web:
	cd web && npm ci && npm run build

## generate: regenerate server stubs and the typed web client from api/openapi.yaml
generate:
	go generate ./...
	cd web && npm run generate

## test: unit and integration tests (integration tests need `make tools` or Docker)
test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## tools: download rqlited for integration tests into .tools/
tools: .tools/rqlite/rqlite-v$(RQLITE_VERSION)-$(GOOS_ARCH)/rqlited

.tools/rqlite/rqlite-v$(RQLITE_VERSION)-$(GOOS_ARCH)/rqlited:
	mkdir -p .tools/rqlite
	curl -fsSL -o .tools/rqlite/rqlite.tar.gz \
		https://github.com/rqlite/rqlite/releases/download/v$(RQLITE_VERSION)/rqlite-v$(RQLITE_VERSION)-$(GOOS_ARCH).tar.gz
	tar -C .tools/rqlite -xzf .tools/rqlite/rqlite.tar.gz
	rm .tools/rqlite/rqlite.tar.gz

clean:
	rm -rf bin web/dist/assets web/dist/index.html
