# DuckJump (palta) — top-level build.
#
#   make build     compile everything (release) into dist/bin
#   make run       launch the dev stack (http://127.0.0.1:8088)
#   make dist      release tarball in dist/
#   make packages  rpm + deb packages with systemd services
#   make help      all targets

VERSION ?= 0.1.0
PROFILE ?= release
DIST    := dist
BIN     := $(DIST)/bin

ifeq ($(PROFILE),release)
CARGO_FLAGS := --release
else
CARGO_FLAGS :=
endif

.DEFAULT_GOAL := help
.PHONY: help build debug web gateway paltad rdp run run-noauth edge stop logs dev-web \
        test test-go test-rust test-web generate dist packages clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- compile ----

build: web gateway paltad rdp ## Compile everything (PROFILE=release) into dist/bin
	@mkdir -p $(BIN)
	cp gateway/bin/palta-gw gateway/bin/palta-agent $(BIN)/
	cp paltad/target/$(PROFILE)/paltad paltad/rdp/target/$(PROFILE)/paltad-rdp $(BIN)/
	@echo "binaries in $(BIN)/ ($(PROFILE)):" && ls -lh $(BIN) | tail -n +2

debug: ## Same as build, without optimizations
	$(MAKE) build PROFILE=debug

web: ## React UI, embedded into palta-gw
	$(MAKE) -C gateway web

gateway: ## palta-gw and palta-agent (Go)
	$(MAKE) -C gateway build

paltad: ## paltad session daemon (Rust)
	cd paltad && cargo build $(CARGO_FLAGS)

rdp: ## paltad-rdp worker (Rust, own workspace)
	cd paltad/rdp && cargo build $(CARGO_FLAGS)

# ---- launch (dev) ----

run: web ## Launch the dev stack with auth: sshd, VNC, RDP test servers + paltad + palta-gw
	deploy/dev.sh

run-noauth: web ## Launch the dev stack with palta-gw -dev (no login)
	DEV=1 deploy/dev.sh

edge: ## Add the simulated edge site (closed network + agent); needs `make run`
	deploy/edge.sh

stop: ## Stop the dev stack and the test containers
	deploy/dev.sh stop

logs: ## Follow paltad and palta-gw logs
	tail -F .dev/paltad.log .dev/gw.log

dev-web: ## UI dev server with hot reload (proxies /api to a running stack)
	cd web && bun run dev

# ---- checks and generated code ----

test: test-go test-rust test-web ## Run every test suite and check generated code

test-go:
	cd gateway && go vet ./... && go test ./... && go run ./cmd/openapi-gen -check

test-rust:
	cd paltad && cargo test
	cd paltad/rdp && cargo test

test-web:
	cd web && bun run typecheck

generate: ## Regenerate sqlc code, the OpenAPI spec and the UI's API types
	$(MAKE) -C gateway generate openapi
	cd web && bun run gen-api

# ---- release ----

dist: build ## Release tarball: dist/duckjump-<version>-linux-amd64.tar.gz
	@rm -rf $(DIST)/duckjump-$(VERSION)
	@mkdir -p $(DIST)/duckjump-$(VERSION)
	cp $(BIN)/* README.md $(DIST)/duckjump-$(VERSION)/
	tar -C $(DIST) -czf $(DIST)/duckjump-$(VERSION)-linux-amd64.tar.gz duckjump-$(VERSION)
	@rm -rf $(DIST)/duckjump-$(VERSION)
	@ls -lh $(DIST)/duckjump-$(VERSION)-linux-amd64.tar.gz

packages: ## rpm + deb with systemd services (duckjump, duckjump-agent) in dist/packages; needs podman or docker
	VERSION=$(VERSION) packaging/build.sh

clean: ## Remove build outputs (keeps .dev data)
	rm -rf $(DIST) gateway/bin/palta-gw gateway/bin/palta-agent
	cd paltad && cargo clean
	cd paltad/rdp && cargo clean
