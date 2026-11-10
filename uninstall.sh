#!/bin/zsh
# Remove Zeke's background jobs, app and CLI link.  Usage: ./uninstall.sh [--purge]
#   --purge also moves ~/.zeke (your history, settings, holds, cached feeds) to the Trash.
set -uo pipefail
ZEKE_HOME="${ZEKE_HOME:-$HOME/.zeke}"
PREFIX="io.github.edamuza.zeke"
U="gui/$(id -u)"
for job in server daily weekly; do
  launchctl bootout "$U/$PREFIX.$job" 2>/dev/null
  rm -f "$HOME/Library/LaunchAgents/$PREFIX.$job.plist"
done
osascript -e 'tell application id "io.github.edamuza.zeke" to quit' 2>/dev/null
APP="${ZEKE_APP_DIR:-/Applications}/Zeke.app"
[[ -d "$APP" ]] && mv "$APP" "$HOME/.Trash/Zeke $(date +%s).app"
[[ -L "$HOME/.local/bin/zeke" ]] && rm "$HOME/.local/bin/zeke"
if [[ "${1:-}" == "--purge" && -d "$ZEKE_HOME" ]]; then
  mv "$ZEKE_HOME" "$HOME/.Trash/zeke-data-$(date +%s)"; echo "Moved $ZEKE_HOME to the Trash."
else
  echo "Kept your data in $ZEKE_HOME (use --purge to remove it)."
fi
echo "Zeke uninstalled."
