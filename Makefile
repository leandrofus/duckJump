# DuckJump — top-level build.
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
.PHONY: help build debug web gateway duckjumpd rdp run run-noauth edge stop logs dev-web \
        test test-go test-rust test-web test-oidc test-postgres test-s3 test-sftp minio minio-stop keycloak keycloak-stop postgres postgres-stop generate dist packages clean \
        website website-dev website-build

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- compile ----

build: web gateway duckjumpd rdp ## Compile everything (PROFILE=release) into dist/bin
	@mkdir -p $(BIN)
	cp gateway/bin/duckjump-gw gateway/bin/duckjump-agent $(BIN)/
	cp duckjumpd/target/$(PROFILE)/duckjumpd duckjumpd/rdp/target/$(PROFILE)/duckjumpd-rdp $(BIN)/
	@echo "binaries in $(BIN)/ ($(PROFILE)):" && ls -lh $(BIN) | tail -n +2

debug: ## Same as build, without optimizations
	$(MAKE) build PROFILE=debug

web: ## React UI, embedded into duckjump-gw
	$(MAKE) -C gateway web

gateway: ## duckjump-gw and duckjump-agent (Go)
	$(MAKE) -C gateway build

duckjumpd: ## duckjumpd session daemon (Rust)
	cd duckjumpd && cargo build $(CARGO_FLAGS)

rdp: ## duckjumpd-rdp worker (Rust, own workspace)
	cd duckjumpd/rdp && cargo build $(CARGO_FLAGS)

# ---- launch (dev) ----

run: web ## Launch the dev stack with auth: sshd, VNC, RDP test servers + duckjumpd + duckjump-gw
	deploy/dev.sh

run-noauth: web ## Launch the dev stack with duckjump-gw -dev (no login)
	DEV=1 deploy/dev.sh

edge: ## Add the simulated edge site (closed network + agent); needs `make run`
	deploy/edge.sh

stop: ## Stop the dev stack and the test containers
	deploy/dev.sh stop

logs: ## Follow duckjumpd and duckjump-gw logs
	tail -F .dev/duckjumpd.log .dev/gw.log

dev-web: ## UI dev server with hot reload (proxies /api to a running stack)
	cd web && bun run dev

website: website-build ## Build the Astro GitHub Pages documentation website

website-dev: ## Run local dev server for the Astro documentation website
	cd website && bun run dev

website-build: ## Compile the Astro documentation website into website/dist
	cd website && bun run build

# ---- checks and generated code ----

test: test-go test-rust test-web test-oidc test-postgres test-s3 test-sftp ## Run every test suite and check generated code (SKIP_OIDC=1, SKIP_PG=1, SKIP_S3=1, SKIP_SFTP=1 skip the container ones)

test-go:
	cd gateway && go vet ./... && go test ./... && go run ./cmd/openapi-gen -check

test-rust:
	cd duckjumpd && cargo test
	cd duckjumpd/rdp && cargo test

test-web:
	cd web && bun install --frozen-lockfile && bun run typecheck

# Single sign-on against a real Keycloak (docker or podman). Reuses one
# already running (make keycloak); otherwise starts one and removes it after.
KEYCLOAK_ISSUER := http://127.0.0.1:18180/realms/duckjump
test-oidc: ## SSO tests against Keycloak in a container
	@if [ -n "$(SKIP_OIDC)" ]; then echo "test-oidc: skipped (SKIP_OIDC)"; exit 0; fi; \
	if ! command -v docker >/dev/null && ! command -v podman >/dev/null; then echo "test-oidc: skipped (no docker or podman)"; exit 0; fi; \
	started=; \
	if ! curl -fs $(KEYCLOAK_ISSUER)/.well-known/openid-configuration >/dev/null 2>&1; then deploy/keycloak.sh start || exit 1; started=1; fi; \
	cd gateway && DUCKJUMP_TEST_KEYCLOAK=$(KEYCLOAK_ISSUER) go test -count=1 -run 'Keycloak' ./internal/server/; rc=$$?; \
	cd .. && if [ -n "$$started" ]; then deploy/keycloak.sh stop; fi; exit $$rc

# The gateway suites again on PostgreSQL (each test in its own schema).
POSTGRES_URL := postgres://duckjump:duckjump@127.0.0.1:25432/duckjump?sslmode=disable
test-postgres: ## Gateway tests against PostgreSQL in a container
	@if [ -n "$(SKIP_PG)" ]; then echo "test-postgres: skipped (SKIP_PG)"; exit 0; fi; \
	if ! command -v docker >/dev/null && ! command -v podman >/dev/null; then echo "test-postgres: skipped (no docker or podman)"; exit 0; fi; \
	started=; \
	if ! (docker exec duckjump-postgres pg_isready -q || podman exec duckjump-postgres pg_isready -q) >/dev/null 2>&1; then deploy/postgres.sh start || exit 1; started=1; fi; \
	cd gateway && DUCKJUMP_TEST_POSTGRES='$(POSTGRES_URL)' go test -count=1 ./internal/...; rc=$$?; \
	cd .. && if [ -n "$$started" ]; then deploy/postgres.sh stop; fi; exit $$rc

# Recordings in S3: duckjumpd uploads (Rust) and the gateway reads, sizes and
# purges (Go), against MinIO.
test-s3: ## Recording storage tests against MinIO in a container
	@if [ -n "$(SKIP_S3)" ]; then echo "test-s3: skipped (SKIP_S3)"; exit 0; fi; \
	if ! command -v docker >/dev/null && ! command -v podman >/dev/null; then echo "test-s3: skipped (no docker or podman)"; exit 0; fi; \
	started=; \
	if ! curl -fs http://127.0.0.1:19000/minio/health/ready >/dev/null 2>&1; then deploy/minio.sh start || exit 1; started=1; fi; \
	eval "$$(deploy/minio.sh env)"; export DUCKJUMP_TEST_S3=1; \
	(cd duckjumpd && cargo test -q -p duckjumpd s3 && cargo test -q -p duckjumpd --test daemon recording_moves_to_s3) && \
	(cd gateway && go test -count=1 -run 'S3' ./internal/server/); rc=$$?; \
	if [ -n "$$started" ]; then deploy/minio.sh stop; fi; exit $$rc

# File transfer: duckjumpd's SFTP sessions against a real OpenSSH server.
test-sftp: ## File transfer tests against OpenSSH in a container
	@if [ -n "$(SKIP_SFTP)" ]; then echo "test-sftp: skipped (SKIP_SFTP)"; exit 0; fi; \
	if ! command -v docker >/dev/null && ! command -v podman >/dev/null; then echo "test-sftp: skipped (no docker or podman)"; exit 0; fi; \
	started=; \
	if ! (exec 3<>/dev/tcp/127.0.0.1/12222) 2>/dev/null; then deploy/sshd.sh start || exit 1; started=1; fi; \
	(cd duckjumpd && DUCKJUMP_TEST_SSH=127.0.0.1:12222 cargo test -q -p duckjumpd --test daemon sftp_session); rc=$$?; \
	if [ -n "$$started" ]; then deploy/sshd.sh stop; fi; exit $$rc

minio: ## Start MinIO for development (eval "$$(deploy/minio.sh env)")
	deploy/minio.sh start

minio-stop: ## Stop MinIO
	deploy/minio.sh stop

postgres: ## Start PostgreSQL for development (DUCKJUMP_DB=$$(deploy/postgres.sh url))
	deploy/postgres.sh start

postgres-stop: ## Stop PostgreSQL
	deploy/postgres.sh stop

keycloak: ## Start Keycloak with the test realm (SSO for make run: eval "$$(deploy/keycloak.sh env)")
	deploy/keycloak.sh start

keycloak-stop: ## Stop Keycloak
	deploy/keycloak.sh stop

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
	rm -rf $(DIST) gateway/bin/duckjump-gw gateway/bin/duckjump-agent
	cd duckjumpd && cargo clean
	cd duckjumpd/rdp && cargo clean
