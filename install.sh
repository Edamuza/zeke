#!/bin/zsh
# Install (or upgrade) Zeke for the current user.  Usage: ./install.sh [--no-app]
#   Runtime + data:  ~/.zeke   (override with ZEKE_HOME=...)
#   App:             /Applications/Zeke.app   (ZEKE_APP_DIR=... to change; skip with --no-app)
#   Background jobs: ~/Library/LaunchAgents/io.github.edamuza.zeke.{server,daily,weekly}.plist
# Safe to re-run: code is replaced, your data/ and config.json are kept.
set -euo pipefail
REPO="${0:A:h}"
ZEKE_HOME="${ZEKE_HOME:-$HOME/.zeke}"
PREFIX="io.github.edamuza.zeke"
LA="$HOME/Library/LaunchAgents"
U="gui/$(id -u)"
NO_APP=0; [[ "${1:-}" == "--no-app" ]] && NO_APP=1

say() { print -P "%F{cyan}→%f $*"; }
die() { print -P "%F{red}✗%f $*" >&2; exit 1; }

# ---- checks
[[ "$(uname)" == "Darwin" ]] || die "Zeke is for macOS."
major=$(sw_vers -productVersion | cut -d. -f1); (( major >= 14 )) || die "macOS 14 or newer required."
/usr/bin/python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null \
  || die "/usr/bin/python3 (3.9+) missing — run: xcode-select --install"
if (( ! NO_APP )); then command -v swiftc >/dev/null || die "swiftc missing — run: xcode-select --install (or use --no-app)"; fi
command -v brew >/dev/null || print -P "%F{yellow}!%f Homebrew not found — Homebrew sources will be skipped."

# ---- runtime
say "installing runtime to $ZEKE_HOME"
mkdir -p "$ZEKE_HOME"/{data,logs,bin}; chmod 700 "$ZEKE_HOME/data"
rm -rf "$ZEKE_HOME/checks" "$ZEKE_HOME/ui"
cp -R "$REPO/src/checks" "$REPO/src/ui" "$ZEKE_HOME/"
cp "$REPO/src/engine.py" "$REPO/src/server.py" "$REPO/scripts/daily-gate.sh" "$REPO/scripts/zeke" "$ZEKE_HOME/"
chmod +x "$ZEKE_HOME/daily-gate.sh" "$ZEKE_HOME/zeke"
find "$ZEKE_HOME" -name __pycache__ -prune -exec rm -rf {} +

# Your login shell's PATH, so launchd jobs find the same brew/node/npm/uv/CLIs you use.
# Interactive login shell (-lic) so PATH additions from .zshrc/.bashrc count too; markers ignore any banner output.
LOGIN_PATH="$(${SHELL:-/bin/zsh} -lic 'printf "__ZP__%s__ZP__" "$PATH"' 2>/dev/null </dev/null | sed -n 's/.*__ZP__\(.*\)__ZP__.*/\1/p' || true)"
[[ -n "$LOGIN_PATH" ]] || LOGIN_PATH="$PATH"
if [[ ! -f "$ZEKE_HOME/config.json" ]]; then
  /usr/bin/python3 -c 'import json,sys; json.dump({"path": sys.argv[1], "npm_prefixes": [], "ignore_apps": []}, open(sys.argv[2], "w"), indent=1)' \
    "$LOGIN_PATH" "$ZEKE_HOME/config.json"
  say "wrote $ZEKE_HOME/config.json (edit to add npm prefixes or apps to ignore)"
fi
JOB_PATH="$(/usr/bin/python3 -c 'import json,sys; p=json.load(open(sys.argv[1])).get("path",""); d="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"; print(":".join(dict.fromkeys([x for x in (p+":"+d).split(":") if x.startswith("/")])))' "$ZEKE_HOME/config.json")"

# ---- app + helper
if (( ! NO_APP )); then
  say "building Zeke.app"
  ZEKE_HOME="$ZEKE_HOME" "$REPO/app/build.sh" --install
fi

# ---- launchd jobs
say "installing background jobs"
mkdir -p "$LA"
for job in server daily weekly; do
  dst="$LA/$PREFIX.$job.plist"
  launchctl bootout "$U/$PREFIX.$job" 2>/dev/null || true
  sed -e "s|__PREFIX__|$PREFIX|g" -e "s|__ZEKE_HOME__|$ZEKE_HOME|g" -e "s|__PATH__|$JOB_PATH|g" \
    "$REPO/launchd/$job.plist.in" > "$dst"
  plutil -lint -s "$dst"
  launchctl bootstrap "$U" "$dst"
done

# ---- CLI
if [[ -d "$HOME/.local/bin" ]]; then ln -sf "$ZEKE_HOME/zeke" "$HOME/.local/bin/zeke"; say "linked ~/.local/bin/zeke"; fi

# ---- first scan
for i in {1..20}; do curl -s "http://127.0.0.1:${ZEKE_PORT:-47800}/api/health" | grep -q '"zeke"' && break; sleep 0.5; done
say "first scan and security data download (runs in the background)"
( /usr/bin/python3 "$ZEKE_HOME/engine.py" feeds >/dev/null 2>&1; /usr/bin/python3 "$ZEKE_HOME/engine.py" scan --trigger install >/dev/null 2>&1 ) &!
(( NO_APP )) || open "${ZEKE_APP_DIR:-/Applications}/Zeke.app"
print -P "%F{green}✓%f Zeke is installed. Dashboard: open Zeke.app, or run: $ZEKE_HOME/zeke open"
