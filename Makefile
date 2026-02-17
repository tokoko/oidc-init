.PHONY: build test test-go test-python test-integration test-all \
        lint lint-go lint-python fmt fmt-go fmt-python \
        setup teardown clean

BINARY_NAME ?= oidc
CGO_ENABLED ?= 0
export CGO_ENABLED

# ── Build ──────────────────────────────────────────────────
build:
	go build -o $(BINARY_NAME) .

# ── Test ───────────────────────────────────────────────────
test: test-go test-python

test-go:
	go test ./...

test-python:
	cd sdks/python && uv run pytest

test-integration:
	go test -v -tags integration ./...

test-all: test test-integration

# ── Lint ───────────────────────────────────────────────────
lint: lint-go lint-python

lint-go:
	go vet ./...

lint-python:
	cd sdks/python && uv run ruff check .
	cd sdks/python && uv run ty check oidc_init

# ── Format ─────────────────────────────────────────────────
fmt: fmt-go fmt-python

fmt-go:
	gofmt -w .

fmt-python:
	cd sdks/python && uv run black .

# ── Keycloak ───────────────────────────────────────────────
setup:
	docker compose up -d
	@echo "Waiting for Keycloak..."
	@until curl -sf http://localhost:8080/realms/master > /dev/null 2>&1; do sleep 1; done
	./scripts/setup_keycloak.sh

teardown:
	docker compose down

# ── Clean ──────────────────────────────────────────────────
clean:
	rm -f $(BINARY_NAME)
