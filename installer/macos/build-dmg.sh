#!/usr/bin/env bash
# Build a macOS .app bundle and a .dmg from an already built universal binary.
#
# Usage: build-dmg.sh <binary> <version> <output.dmg>
#
# The bundle is ad-hoc signed so it launches locally. Set MACOS_SIGN_IDENTITY to
# a Developer ID identity to sign it for distribution; notarization is not
# automated yet.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <binary> <version> <output.dmg>" >&2
  exit 2
fi

binary="$1"
version="$2"
output="$3"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

work="$(mktemp -d "${TMPDIR:-/tmp}/go-smart-proxy-dmg.XXXXXX")"
trap 'rm -rf "$work"' EXIT

app="$work/Go Smart Proxy.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/proxy"
chmod +x "$app/Contents/MacOS/proxy"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"

if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  codesign --force --deep --options runtime --sign "$MACOS_SIGN_IDENTITY" "$app"
else
  # Ad-hoc signature: enough to launch the app on the machine that built it.
  codesign --force --deep --sign - "$app"
fi

stage="$work/dmg"
mkdir -p "$stage"
cp -R "$app" "$stage/"
cp "$root/README.md" "$root/LICENSE" "$stage/"
ln -s /Applications "$stage/Applications"

mkdir -p "$(dirname "$output")"
rm -f "$output"
hdiutil create -volname "Go Smart Proxy $version" -srcfolder "$stage" -ov -format UDZO "$output"
echo "created $output"
