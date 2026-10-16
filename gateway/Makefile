SQLC_VERSION := 1.31.1
# sha256 of sqlc_$(SQLC_VERSION)_linux_amd64.tar.gz (the release ships no checksums file)
SQLC_SHA256 := 497ae4fcdfa64c5b0c311ffe4c2bd991e43991e82e5367792ed78bc2dca27354
SQLC := bin/sqlc

.PHONY: generate openapi web test build

# Regenerates internal/store/db from migrations + queries.
generate: $(SQLC)
	$(SQLC) generate

$(SQLC):
	@mkdir -p bin
	cd bin && curl -fsSL -o sqlc.tgz https://github.com/sqlc-dev/sqlc/releases/download/v$(SQLC_VERSION)/sqlc_$(SQLC_VERSION)_linux_amd64.tar.gz \
	  && echo "$(SQLC_SHA256)  sqlc.tgz" | sha256sum -c - \
	  && tar xzf sqlc.tgz sqlc && rm sqlc.tgz

# Regenerates openapi/openapi.yaml from openapi:operation / openapi:schema comments.
openapi:
	go run ./cmd/openapi-gen

# Builds the React UI into internal/server/ui/dist (embedded by duckjump-gw).
web:
	cd ../web && bun install --frozen-lockfile && bun run gen-api && bun run build
	touch internal/server/ui/dist/.gitkeep

test:
	go test ./...

build:
	go build -o bin/duckjump-gw ./cmd/duckjump-gw
	CGO_ENABLED=0 go build -ldflags='-s -w' -o bin/duckjump-agent ./cmd/duckjump-agent
