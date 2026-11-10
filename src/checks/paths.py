"""Shared paths.

ZEKE_HOME     where Zeke's runtime lives (default ~/.zeke; install.sh copies src/ here)
ZEKE_DATA_DIR overrides the data directory (tests use a temp dir so they never touch real data)
"""
import os

HOME = os.path.expanduser("~")
BASE = os.environ.get("ZEKE_HOME") or os.path.join(HOME, ".zeke")
DATA = os.environ.get("ZEKE_DATA_DIR") or os.path.join(BASE, "data")
FEEDS = os.path.join(DATA, "feeds")
SECURITY = os.path.join(DATA, "security.json")
SEC_STATE = os.path.join(DATA, "security-state.json")
HOLDS = os.path.join(DATA, "holds.json")
CONFIG = os.path.join(BASE, "config.json")

# Identity. Change LABEL_PREFIX/APP_BUNDLE_ID together with app/Info.plist and launchd/ if you fork.
APP_NAME = "Zeke"
APP_BUNDLE_ID = "io.github.edamuza.zeke"
LABEL_PREFIX = "io.github.edamuza.zeke"
PORT = int(os.environ.get("ZEKE_PORT", "47800"))
VERSION = "0.1.0"

for d in (DATA, FEEDS):
    os.makedirs(d, exist_ok=True)
try:
    os.chmod(DATA, 0o700)
except OSError:
    pass
