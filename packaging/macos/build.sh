#!/usr/bin/env bash
# Fabrique dans dist/ l'application macOS (NetBuster.app) et son image disque (.dmg),
# pour les Mac Apple Silicon et Intel. À lancer sur un Mac, avec Rust et les outils de Xcode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

for t in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add "$t"
    MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --locked --target "$t"
done

DIST="$ROOT/dist"
APP="$DIST/NetBuster.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/netbuster" \
    "$TARGET_DIR/aarch64-apple-darwin/release/netbuster" \
    "$TARGET_DIR/x86_64-apple-darwin/release/netbuster"
sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
cp assets/macos/netbuster.icns "$APP/Contents/Resources/netbuster.icns"
cp LICENSE "$APP/Contents/Resources/LICENSE"
# Signature locale, sans compte développeur : macOS demandera une confirmation au premier lancement.
codesign --force --deep --sign - "$APP"

STAGE="$DIST/.dmg"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="$DIST/netbuster-$VERSION-macos-universal.dmg"
rm -f "$DMG"
hdiutil create -volname NetBuster -srcfolder "$STAGE" -ov -format UDZO "$DMG"
rm -rf "$STAGE"
ls -lh "$DMG"
