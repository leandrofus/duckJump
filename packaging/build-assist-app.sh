#!/bin/sh
# Builds the duckJump Assist desktop app installers (AppImage, deb) in a
# container, so the host needs neither WebKitGTK nor the Tauri CLI, and puts
# them in dist/bin, where the gateway serves them from the join page.
# Debian 12 base: the AppImage runs on glibc 2.36+ (Ubuntu 22.04+ is 2.35:
# use the deb there, or set ASSIST_IMAGE to an older base).
set -eu
cd "$(dirname "$0")/.."
: "${ASSIST_IMAGE:=docker.io/library/rust:1-bookworm}"
ENGINE=$(command -v podman || command -v docker)
TAG=duckjump-assist-build
OUT=dist/bin
TARGET=dist/build/assist-app-target

# Build image: system libraries and the Tauri CLI, cached between runs.
$ENGINE build -q -t "$TAG" - >/dev/null <<EOF
FROM $ASSIST_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev libxdo-dev \
      libayatana-appindicator3-dev file desktop-file-utils patchelf \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install tauri-cli --version '^2' --locked
EOF

mkdir -p "$HOME/.cargo/registry" "$HOME/.cargo/git" "$TARGET" "$OUT"
# APPIMAGE_EXTRACT_AND_RUN: linuxdeploy is itself an AppImage, and
# containers have no FUSE.
$ENGINE run --rm --security-opt label=disable \
	-e APPIMAGE_EXTRACT_AND_RUN=1 -e CARGO_TARGET_DIR=/src/$TARGET \
	-v "$PWD:/src" -v "$HOME/.cargo/registry:/usr/local/cargo/registry" -v "$HOME/.cargo/git:/usr/local/cargo/git" \
	-w /src/duckjumpd/assist-app "$TAG" sh -euc "
		cargo tauri build --bundles appimage,deb -- --locked
		chown -R $(id -u):$(id -g) /src/$TARGET /usr/local/cargo/registry /usr/local/cargo/git"

cp "$TARGET"/release/bundle/appimage/*.AppImage "$OUT/duckjump-assist-app.AppImage"
cp "$TARGET"/release/bundle/deb/*.deb "$OUT/duckjump-assist-app.deb"
chmod +x "$OUT/duckjump-assist-app.AppImage"
ls -lh "$OUT"/duckjump-assist-app.*
