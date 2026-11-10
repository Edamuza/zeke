#!/bin/zsh
# Builds Zeke.app and the zeke-apps helper.
#   ./build.sh                 build into app/build/
#   ./build.sh --install       also install Zeke.app to $ZEKE_APP_DIR (default /Applications)
#                              and the helper to $ZEKE_HOME/bin (default ~/.zeke/bin)
# Needs Xcode Command Line Tools (swiftc). Apps are ad-hoc signed (local use).
set -euo pipefail
cd "${0:A:h}"
ZEKE_HOME="${ZEKE_HOME:-$HOME/.zeke}"
APP_DIR="${ZEKE_APP_DIR:-/Applications}"
ARCH="$(uname -m)"            # arm64 or x86_64
TARGET="$ARCH-apple-macos14"
APP="Zeke.app"
B="build"

rm -rf "$B" && mkdir -p "$B/$APP/Contents/MacOS" "$B/$APP/Contents/Resources" "$B/icon.iconset"

echo "→ icon"
swiftc -O -o "$B/icon" icon.swift
"$B/icon" "$B/icon-1024.png"
for s in 16 32 128 256 512; do
  sips -z $s $s "$B/icon-1024.png" --out "$B/icon.iconset/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$B/icon-1024.png" --out "$B/icon.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$B/icon.iconset" -o "$B/$APP/Contents/Resources/AppIcon.icns"

echo "→ Zeke.app ($ARCH)"
swiftc -O -swift-version 5 -target "$TARGET" -o "$B/$APP/Contents/MacOS/Zeke" main.swift
cp Info.plist "$B/$APP/Contents/Info.plist"
codesign --force --sign - --timestamp=none "$B/$APP"

echo "→ zeke-apps helper"
swiftc -O -swift-version 5 -target "$TARGET" -o "$B/zeke-apps" apps-helper.swift
codesign --force --sign - "$B/zeke-apps"

if [[ "${1:-}" == "--install" ]]; then
  echo "→ install $APP_DIR/$APP and $ZEKE_HOME/bin/zeke-apps"
  osascript -e 'tell application id "io.github.edamuza.zeke" to quit' 2>/dev/null || true
  rm -rf "$APP_DIR/$APP"
  cp -R "$B/$APP" "$APP_DIR/$APP"
  mkdir -p "$ZEKE_HOME/bin"
  cp "$B/zeke-apps" "$ZEKE_HOME/bin/zeke-apps"
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP_DIR/$APP" || true
fi
echo "✓ done"
