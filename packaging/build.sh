#!/bin/sh
# Builds the rpm and deb packages (amd64) into dist/packages:
#   duckjump        gateway + duckjumpd + RDP worker, systemd services, and
#                   what the gateway serves for remote support: the
#                   duckjump-assist CLI and the duckJump Assist app installers
#   duckjump-agent  edge agent, systemd service
# Go builds static (CGO off). Rust builds in a Debian 11 container so the
# binaries need only glibc 2.31: RHEL/Rocky/Alma 9+, Debian 11+, Ubuntu 22.04+.
set -eu
cd "$(dirname "$0")/.."
: "${VERSION:=0.1.0}"
: "${ARCH:=amd64}"
: "${MAINTAINER:=DuckJump <duckjump@localhost>}"
: "${RUST_IMAGE:=docker.io/library/rust:1.91-bullseye}"
NFPM_VERSION=v2.43.0
ENGINE=$(command -v podman || command -v docker)
OUT=dist/pkg
mkdir -p "$OUT" dist/packages dist/build

echo "→ UI"
make -s web >/dev/null

echo "→ duckjump, duckjump-agent (Go, static)"
(cd gateway &&
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "../$OUT/duckjump" ./cmd/duckjump-gw &&
	ln -sf duckjump "../$OUT/duckjump-gw" &&
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "../$OUT/duckjump-agent" ./cmd/duckjump-agent)

echo "→ duckjumpd, duckjumpd-rdp (Rust, $RUST_IMAGE)"
mkdir -p "$HOME/.cargo/registry" "$HOME/.cargo/git"
$ENGINE run --rm --security-opt label=disable \
	-v "$PWD:/src" -v "$HOME/.cargo/registry:/usr/local/cargo/registry" -v "$HOME/.cargo/git:/usr/local/cargo/git" \
	-w /src "$RUST_IMAGE" sh -euc '
		cargo build --release --locked --manifest-path duckjumpd/Cargo.toml --target-dir dist/build/target
		cargo build --release --locked --manifest-path duckjumpd/rdp/Cargo.toml --target-dir dist/build/target-rdp
		strip dist/build/target/release/duckjumpd dist/build/target/release/duckjump-assist dist/build/target-rdp/release/duckjumpd-rdp'
cp dist/build/target/release/duckjumpd dist/build/target/release/duckjump-assist dist/build/target-rdp/release/duckjumpd-rdp "$OUT/"

# guard: highest glibc symbol version the Rust binaries need
for f in "$OUT/duckjumpd" "$OUT/duckjumpd-rdp" "$OUT/duckjump-assist"; do
	max=$(strings "$f" | grep -o 'GLIBC_2\.[0-9]*' | sort -t. -k2 -n -u | tail -1)
	echo "  $f needs $max"
	case $max in GLIBC_2.3[2-9] | GLIBC_2.[4-9]*) echo "glibc too new: $max" >&2; exit 1 ;; esac
done

echo "→ duckJump Assist app (AppImage, deb)"
packaging/build-assist-app.sh
cp dist/bin/duckjump-assist-app.AppImage dist/bin/duckjump-assist-app.deb "$OUT/"

NFPM=dist/build/nfpm
[ -x "$NFPM" ] || GOBIN="$PWD/dist/build" go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION"
for cfg in packaging/nfpm-duckjump.yaml packaging/nfpm-agent.yaml; do
	for fmt in rpm deb; do
		VERSION=$VERSION ARCH=$ARCH MAINTAINER=$MAINTAINER "$NFPM" package -f "$cfg" -p "$fmt" -t dist/packages/
	done
done
ls -lh dist/packages
