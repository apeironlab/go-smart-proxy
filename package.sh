#!/usr/bin/env bash
# Build the web UI and create desktop packages for macOS, Windows and Linux.
#
# Usage: ./package.sh [version]
#
# macOS builds a universal (arm64 + amd64) binary and requires Xcode Command
# Line Tools. Windows is cross-compiled from any host. Linux is built inside
# Docker with GTK/AppIndicator, so the resulting binary needs those libraries at
# runtime. Set LINUX_ARCHS="amd64 arm64" to build more than one architecture.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"

version="${1:-${VERSION:-}}"
if [[ -z "$version" ]]; then
  version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
fi
version="${version//\//-}"
dist="$root/dist"

echo "==> Building web UI"
make webui >/dev/null

echo "==> Packaging go-smart-proxy $version"
rm -rf "$dist"
mkdir -p "$dist"
stage="$dist/.stage"

copy_docs() {
  cp README.md LICENSE "$1/"
}

# macOS: universal binary (Apple Silicon + Intel).
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> macOS (universal)"
  mac_arm="$stage/darwin-arm64"
  mac_intel="$stage/darwin-amd64"
  mkdir -p "$mac_arm" "$mac_intel"

  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -trimpath -ldflags "-s -w" -o "$mac_arm/proxy" .

  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="clang -arch x86_64" \
    go build -trimpath -ldflags "-s -w" -o "$mac_intel/proxy" .

  mac_out="$stage/darwin-universal"
  mkdir -p "$mac_out"
  lipo -create -output "$mac_out/proxy" "$mac_arm/proxy" "$mac_intel/proxy"
  copy_docs "$mac_out"
  tar -czf "$dist/go-smart-proxy_${version}_darwin_universal.tar.gz" -C "$mac_out" .
else
  echo "==> macOS skipped (not running on Darwin)" >&2
fi

# Windows: pure Go, GUI subsystem (no console window).
echo "==> Windows (amd64)"
win_out="$stage/windows-amd64"
mkdir -p "$win_out"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -H=windowsgui" -o "$win_out/proxy.exe" .
copy_docs "$win_out"
(cd "$win_out" && zip -q -r "$dist/go-smart-proxy_${version}_windows_amd64.zip" .)

# Linux: CGO build inside Docker so GTK/AppIndicator headers are available.
if command -v docker >/dev/null 2>&1; then
  for arch in ${LINUX_ARCHS:-amd64}; do
    echo "==> Linux ($arch, Docker)"
    linux_out="$stage/linux-$arch"
    mkdir -p "$linux_out"
    docker run --rm --platform "linux/$arch" \
      -v "$root":/src -v "$linux_out":/out -w /src \
      -e CGO_ENABLED=1 -e GOOS=linux -e GOARCH="$arch" \
      golang:1.24-bookworm bash -c '
        apt-get update -qq &&
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
          gcc pkg-config libgtk-3-dev libayatana-appindicator3-dev >/dev/null &&
        go build -trimpath -ldflags "-s -w" -o /out/proxy .
      '
    copy_docs "$linux_out"
    tar -czf "$dist/go-smart-proxy_${version}_linux_${arch}.tar.gz" -C "$linux_out" .
  done
else
  echo "==> Linux skipped: Docker not found" >&2
fi

rm -rf "$stage"

echo "==> Checksums"
(cd "$dist" && shasum -a 256 ./*.tar.gz ./*.zip > SHA256SUMS)

echo
ls -lh "$dist"
