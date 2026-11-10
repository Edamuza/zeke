#!/usr/bin/python3
"""Zeke engine — the only code that scans or updates. See docs/SPEC.md.

CLI:
  engine.py scan [--deep] [--trigger T] [--notify]
  engine.py update <id> [<id> ...] [--trigger T]
  engine.py update-all [--trigger T]
  engine.py plan                      (print what update-all would do)
  engine.py daily                     (feeds, then update-all if daily auto-update is on)
  engine.py feeds [--force]           (refresh vulnerability/patch feeds; own lock)
  engine.py hold <id> hold|skip|none [version]
  engine.py mute <finding-id> [days|off]
  engine.py open <id>
  engine.py open-dashboard
  engine.py status
Runs on /usr/bin/python3 (3.9, stdlib only).
"""
import concurrent.futures
import datetime
import fcntl
import glob
import json
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402
from checks import feeds, net, paths  # noqa: E402

HOME = os.path.expanduser("~")
BASE = paths.BASE
DATA = paths.DATA
RUNS = os.path.join(DATA, "runs")
LOGS = os.path.join(DATA, "logs") if os.environ.get("ZEKE_DATA_DIR") else os.path.join(BASE, "logs")
FEEDS_LOCK = os.path.join(DATA, "feeds.lock")
KEEP_RUNS = 200
NAME_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$")
INVENTORY = os.path.join(DATA, "inventory.json")
CURRENT = os.path.join(DATA, "current.json")
SETTINGS = os.path.join(DATA, "settings.json")
LOCKFILE = os.path.join(DATA, "engine.lock")
CASK_CATALOG = os.path.join(DATA, "cask-catalog.json")
BUSY_EXIT = 75
STEP_TIMEOUT = 30 * 60


def _config():
    try:
        with open(paths.CONFIG) as f:
            return json.load(f)
    except Exception:
        return {}


CONFIG = _config()
# launchd starts us with a minimal PATH. install.sh records your login shell's PATH in config.json.
_DEFAULT_PATH = [os.path.join(HOME, ".local/bin"), "/opt/homebrew/bin", "/opt/homebrew/sbin",
                 "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
PATH = ":".join(dict.fromkeys([p for p in str(CONFIG.get("path", "")).split(":") if p.startswith("/")]
                              + _DEFAULT_PATH))
ENV = dict(os.environ, PATH=PATH, HOMEBREW_NO_ENV_HINTS="1", HOMEBREW_NO_AUTO_UPDATE="1",
           NONINTERACTIVE="1", CI="1", NO_COLOR="1", HOMEBREW_NO_COLOR="1",
           HOMEBREW_NO_ANALYTICS="1")
ENV.pop("SUDO_ASKPASS", None)


def which(name):
    return shutil.which(name, path=PATH)


# ---- tools (each is optional; a missing tool just means that source isn't listed)
BREW = which("brew")
BREW_PREFIX = os.path.dirname(os.path.dirname(os.path.realpath(BREW))) if BREW else None
if BREW_PREFIX and BREW_PREFIX.endswith("/Homebrew"):  # Intel: /usr/local/Homebrew/bin/brew
    BREW_PREFIX = os.path.dirname(BREW_PREFIX)
# Ruby gems / pip only from Homebrew's Ruby and Python (system Ruby/Python packages need sudo).
GEM = os.path.join(BREW_PREFIX, "opt", "ruby", "bin", "gem") if BREW_PREFIX else None
GEM = GEM if GEM and os.path.exists(GEM) else None
PIP = os.path.join(BREW_PREFIX, "bin", "pip3") if BREW_PREFIX else None
PIP = PIP if PIP and os.path.exists(PIP) else None
UV = which("uv")
UC_APPS = os.path.join(BASE, "bin", "zeke-apps")  # native helper: running / quit / open (app/apps-helper.swift)
SELF_BUNDLES = {paths.APP_BUNDLE_ID} | set(CONFIG.get("ignore_apps", []))


def _discover_npms():
    """Every Node install with its own global packages: Homebrew's node, any `node` on PATH
    (nvm/fnm/asdf/app-bundled), plus config.json "npm_prefixes". Keyed by a slug of the prefix."""
    prefixes = []
    if BREW_PREFIX:
        prefixes.append(BREW_PREFIX)
    for d in PATH.split(":"):
        n = os.path.join(d, "node")
        if os.path.exists(n):
            prefixes.append(os.path.dirname(os.path.dirname(os.path.realpath(n))))
    prefixes += [os.path.expanduser(p) for p in CONFIG.get("npm_prefixes", [])]
    out, seen = {}, set()
    for pre in prefixes:
        rp = os.path.realpath(pre)
        node = os.path.join(rp, "bin", "node")
        cli = os.path.join(rp, "lib", "node_modules", "npm", "bin", "npm-cli.js")
        if rp in seen or not (os.path.exists(node) and os.path.exists(cli)):
            continue
        seen.add(rp)
        if BREW_PREFIX and rp == os.path.realpath(BREW_PREFIX):
            key, label = "brew", "npm · Homebrew node"
        else:
            short = rp.replace(HOME, "~", 1)
            key = re.sub(r"[^a-z0-9]+", "-", short.lstrip("~/").lower()).strip("-")[:40] or "node"
            label = "npm · %s" % short
        out[key] = (label, node, cli, rp)
    return out


NPMS = _discover_npms()

# Self-updating CLIs: (id, name, binary, official install locations checked first, update args, latest URL)
SELF_UPDATERS = [
    ("cli:claude", "Claude Code", "claude", ["~/.local/bin/claude"], ["update"],
     "https://registry.npmjs.org/@anthropic-ai/claude-code/latest"),
    ("cli:uv", "uv", "uv", ["~/.local/bin/uv"], ["self", "update"], "https://pypi.org/pypi/uv/json"),
    ("cli:opencode", "opencode", "opencode", ["~/.opencode/bin/opencode"], ["upgrade"], None),
]


def _find_cli(binary, preferred):
    """config.json "cli_paths" override > official install location > first on PATH."""
    for p in [CONFIG.get("cli_paths", {}).get(binary)] + preferred:
        if p and os.access(os.path.expanduser(p), os.X_OK):
            return os.path.expanduser(p)
    return which(binary)


CLIS = {}
for _cid, _name, _bin, _pref, _args, _url in SELF_UPDATERS:
    _p = _find_cli(_bin, _pref)
    if _p:
        CLIS[_cid] = (_name, _p, _args, _url)

PASSWORD_HINTS = ("a terminal is required", "a password is required", "askpass",
                  "sudo: no tty", "must be run with sudo")

for d in (DATA, RUNS, LOGS):
    os.makedirs(d, exist_ok=True)


# ---------------------------------------------------------------- helpers
def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def write_json(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def settings():
    s = {"daily_auto": True, "weekly_check": True, "net_brew_vulns": False, "notify_security": True}
    s.update(read_json(SETTINGS, {}) or {})
    return s


def capture(argv, timeout=300):
    """Run quietly, return (exit, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout


def fetch_json(url, timeout=60):
    """All engine HTTP goes through checks.net, which refuses hosts not in the privacy ledger."""
    return net.get_json(url, timeout=timeout)


def vtuple(v):
    """Leading dotted-numeric part of a version (before ',' build suffix), or None."""
    if not v:
        return None
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(v).split(",")[0])
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def compare(installed, latest):
    """'current' | 'outdated' | 'unknown'.
    A shorter installed version is padded with zeros (2.5 < 2.5.1). A shorter *latest* is compared on
    the shared prefix, so an extra build number on the installed side (6.6.10.70120 vs 6.6.10) is current."""
    a, b = vtuple(installed), vtuple(latest)
    if a is None or b is None:
        return "unknown"
    if len(a) < len(b):
        a = a + (0,) * (len(b) - len(a))
    n = min(len(a), len(b))
    return "outdated" if a[:n] < b[:n] else "current"


def compare_app(installed, latest):
    """Stricter compare for apps matched by name or store listing: (status, note)."""
    a, b = vtuple(installed), vtuple(latest)
    if a is None or b is None or not any(a):
        return "unknown", "installed version unreadable" if a is None or not any(a) else ""
    bb = b
    while len(bb) > 1 and bb[-1] == 0:
        bb = bb[:-1]
    if a[:len(bb)] == bb or (len(bb) >= 3 and any(a[i:i + len(bb)] == bb
                                                  for i in range(1, len(a) - len(bb) + 1))):
        return "current", ""  # exact prefix, or e.g. Brave 157.1.99.55 contains cask 1.99.55
    if a[0] != b[0]:
        return "unknown", "version formats differ (%s vs %s)" % (installed, latest)
    return compare(installed, latest), ""


def item(id, name, source, installed, latest=None, status="unknown", action="none",
         note="", auto=False, **extra):
    d = dict(id=id, name=name, source=source, installed=installed, latest=latest,
             status=status, action=action, note=note, auto=auto)
    d.update(extra)
    return d


# ---------------------------------------------------------------- collectors
# Each returns list of items; raising marks the collector failed (items -> unknown).

BREW_INFO = None


def col_brew():
    code, out, err = capture([BREW, "info", "--json=v2", "--installed"])
    if code != 0:
        raise RuntimeError(err.strip() or "brew info failed")
    info = json.loads(out)
    global BREW_INFO
    BREW_INFO = info
    code, out, err = capture([BREW, "outdated", "--greedy", "--json=v2"])
    if code not in (0, 1):
        raise RuntimeError(err.strip() or "brew outdated failed")
    od = json.loads(out or "{}")
    of = {x["name"]: x for x in od.get("formulae", [])}
    oc = {x["name"]: x for x in od.get("casks", [])}
    items = []
    for f in info.get("formulae", []):
        inst = f["installed"][-1]["version"] if f["installed"] else "?"
        on_req = any(i.get("installed_on_request") for i in f["installed"])
        latest = f["versions"].get("stable")
        if f["versions"].get("bottle") is not None and f.get("revision"):
            latest = "%s_%s" % (latest, f["revision"])
        if f["name"] in of:
            st, latest = "outdated", of[f["name"]].get("current_version", latest)
        else:
            st = "current"
        items.append(item("brew:formula:" + f["name"], f["name"], "Homebrew formulae", inst, latest, st,
                          "update", f.get("desc") or "", True, dependency=not on_req,
                          pinned=bool(f.get("pinned"))))
    # Formulae from taps Homebrew doesn't trust are omitted from `brew info`; list them anyway.
    known = {f["name"] for f in info.get("formulae", [])}
    code, out, _ = capture([BREW, "list", "--formula", "--versions"])
    for line in out.splitlines() if code == 0 else []:
        parts = line.split()
        if parts and parts[0] not in known:
            taps_root = os.path.join(BREW_PREFIX, "Library", "Taps") if os.path.isdir(
                os.path.join(BREW_PREFIX, "Library", "Taps")) else os.path.join(BREW_PREFIX, "Homebrew", "Library", "Taps")
            tap = next((t for t in glob.glob(os.path.join(taps_root, "*", "*"))
                        if glob.glob(os.path.join(t, "**", parts[0] + ".rb"), recursive=True)), "")
            tap = "/".join(tap.split("/")[-2:]).replace("homebrew-", "") if tap else "a third-party tap"
            items.append(item("brew:untrusted:" + parts[0], parts[0], "Homebrew formulae", parts[-1], None,
                              "unknown", "none",
                              "from untrusted tap %s — Homebrew won't check or update it. "
                              "Run `brew trust %s` in Terminal if you trust it." % (tap, tap), False))
    for c in info.get("casks", []):
        name = (c.get("name") or [c["token"]])[0]
        if c["token"] in oc:
            st, latest = "outdated", oc[c["token"]].get("current_version", c["version"])
        else:
            st, latest = "current", c["version"]
        if latest == "latest":
            st = "unknown"
        items.append(item("brew:cask:" + c["token"], name, "Homebrew apps", c.get("installed"), latest, st,
                          "update", c.get("desc") or "", True, token=c["token"],
                          apps=[a if isinstance(a, str) else a.get("target", "")
                                for art in c.get("artifacts", []) if isinstance(art, dict)
                                for a in art.get("app", [])]))
    return items


def npm_argv(key, *args):
    _, node, cli, prefix = NPMS[key]
    return [node, cli, "--prefix", prefix, "-g", "--no-fund", "--no-audit"] + list(args)


def col_npm(key):
    label = NPMS[key][0]
    code, out, err = capture(npm_argv(key, "ls", "--json", "--depth=0"))
    deps = json.loads(out or "{}").get("dependencies", {})
    if code != 0 and not deps:
        raise RuntimeError(err.strip()[:300] or "npm ls failed")
    code, out, err = capture(npm_argv(key, "outdated", "--json"), timeout=180)
    try:
        od = json.loads(out or "{}")
    except ValueError:
        raise RuntimeError("npm outdated returned unreadable output")
    if code not in (0, 1) or (isinstance(od, dict) and "error" in od):
        raise RuntimeError((err.strip() or str(od.get("error")))[:300])
    items = []
    for name, d in sorted(deps.items()):
        o = od.get(name)
        st, latest = ("outdated", o.get("latest")) if o else ("current", d.get("version"))
        items.append(item("npm:%s:%s" % (key, name), name, label, d.get("version"), latest, st,
                          "update", "", True))
    return items


def col_gem():
    code, out, err = capture([GEM, "list", "--local"])
    if code != 0:
        raise RuntimeError(err.strip()[-300:] or "gem list failed")
    code2, out2, err2 = capture([GEM, "outdated"], timeout=180)
    if code2 != 0:
        raise RuntimeError(err2.strip()[-300:] or "gem outdated failed")
    od = {}
    for line in out2.splitlines():
        m = re.match(r"^(\S+) \((\S+) < (\S+)\)", line)
        if m:
            od[m.group(1)] = m.group(3)
    items = []
    for line in out.splitlines():
        m = re.match(r"^(\S+) \((.*)\)$", line)
        if not m:
            continue
        name, vers = m.group(1), m.group(2)
        inst = re.sub(r"^default:\s*", "", vers.split(",")[0].strip())
        default = "default:" in vers
        if name in od:
            st, latest = "outdated", od[name]
        else:
            st, latest = "current", inst
        allv = [re.sub(r"^default:\s*", "", x.strip()) for x in vers.split(",") if x.strip()]
        items.append(item("gem:" + name, name, "Ruby gems", inst, latest, st, "update",
                          "bundled with Ruby" if default else "", True, all_versions=allv,
                          default_version=(re.search(r"default:\s*([^,\s]+)", vers) or [None, None])[1]))
    return items


def col_pip():
    code, out, err = capture([PIP, "list", "--format=json", "--disable-pip-version-check"])
    if code != 0:
        raise RuntimeError(err.strip()[-300:] or "pip list failed")
    allp = json.loads(out)
    code, out, err = capture([PIP, "list", "--outdated", "--format=json", "--disable-pip-version-check"],
                             timeout=180)
    if code != 0:
        raise RuntimeError(err.strip()[-300:] or "pip outdated failed")
    od = {p["name"].lower(): p["latest_version"] for p in json.loads(out or "[]")}
    items = []
    for p in allp:
        if p["name"].lower() == "pip":
            continue  # owned by Homebrew's python formula
        lat = od.get(p["name"].lower())
        items.append(item("pip:" + p["name"], p["name"], "Python packages", p["version"],
                          lat or p["version"], "outdated" if lat else "current", "update",
                          "Homebrew Python — updated only when you click", False))
    return items


def col_uv_tools():
    code, out, err = capture([UV, "tool", "list"])
    if code != 0:
        raise RuntimeError(err.strip() or "uv tool list failed")
    items = []
    for line in out.splitlines():
        m = re.match(r"^(\S+) v(\S+)", line)
        if m:
            items.append(item("uv:" + m.group(1), m.group(1), "uv tools", m.group(2), None, "unknown",
                              "update", "uv can't check without upgrading", True))
    return items


def col_clis():
    items = []
    for cid, (name, binary, args, url) in CLIS.items():
        code, out, _ = capture([binary, "--version"])
        m = re.search(r"\d+(?:\.\d+)+", out or "")
        inst = m.group(0) if code == 0 and m else None
        latest = None
        if url:
            try:
                d = fetch_json(url)
                latest = d.get("version") or (d.get("info") or {}).get("version")
            except Exception:
                latest = None
        st = compare(inst, latest) if inst and latest else "unknown"
        note = "" if url else "self-updater — click Update to check"
        items.append(item(cid, name, "CLI tools", inst, latest, st, "update", note, True))
    return items


def _app_bundles():
    roots = ["/Applications", os.path.join(HOME, "Applications")]
    seen = []
    for r in roots:
        for p in sorted(glob.glob(os.path.join(r, "*.app")) + glob.glob(os.path.join(r, "*", "*.app"))):
            if "/Utilities/" in p or ".localized/" in p:
                continue
            seen.append(p)
    return seen


def _cask_catalog():
    fresh = os.path.exists(CASK_CATALOG) and time.time() - os.path.getmtime(CASK_CATALOG) < 86400
    if not fresh:
        raw = fetch_json("https://formulae.brew.sh/api/cask.json", timeout=30)
        slim = {}
        for c in raw:
            for art in c.get("artifacts", []):
                if isinstance(art, dict) and "app" in art:
                    for a in art["app"]:
                        fn = a if isinstance(a, str) else (a.get("target") or "")
                        fn = os.path.basename(fn).lower()
                        if fn and fn not in slim:
                            slim[fn] = [c["token"], c["version"]]
        write_json(CASK_CATALOG, slim)
    return read_json(CASK_CATALOG, {})


def _store_country():
    code, out, _ = capture(["defaults", "read", "-g", "AppleLocale"], timeout=10)
    m = re.search(r"_([A-Z]{2})", out or "")
    return m.group(1).lower() if m else "us"


def _adam_id(path):
    code, out, _ = capture(["mdls", "-name", "kMDItemAppStoreAdamID", "-raw", path], timeout=20)
    return out.strip() if code == 0 and out.strip().isdigit() else None


def _mas_latest(apps):
    """apps: list of (bundle_id, adam_id). One batched lookup per store, by store id then bundle id."""
    out = {}
    for country in dict.fromkeys([_store_country(), "us"]):
        for key, field in (("id", 1), ("bundleId", 0)):
            missing = [a[field] for a in apps if a[0] not in out and a[field]]
            for i in range(0, len(missing), 50):
                q = urllib.parse.urlencode({key: ",".join(missing[i:i + 50]), "country": country})
                for r in fetch_json("https://itunes.apple.com/lookup?" + q).get("results", []):
                    if r.get("bundleId"):
                        out[r["bundleId"]] = (r.get("version"), r.get("trackId"))
    return out


# Apps whose real version lives outside the .app bundle. Obsidian updates itself by downloading
# obsidian-<version>.asar into Application Support; the bundle version is only the *installer* version,
# which changes when you download a new installer from obsidian.md.
INNER_VERSIONS = {
    "md.obsidian": (os.path.join(HOME, "Library", "Application Support", "obsidian"), r"^obsidian-(\d+(?:\.\d+)+)\.asar$",
                    "https://obsidian.md/download"),
}


def inner_version(bid):
    spec = INNER_VERSIONS.get(bid)
    if not spec:
        return None
    best = None
    try:
        for fn in os.listdir(spec[0]):
            m = re.match(spec[1], fn)
            if m and (best is None or vtuple(m.group(1)) > vtuple(best)):
                best = m.group(1)
    except OSError:
        pass
    return best


def col_apps(brew_items):
    cask_apps = set()
    for it in brew_items:
        for a in it.get("apps") or []:
            cask_apps.add(os.path.basename(a).lower())
        if it["id"].startswith("brew:cask:"):
            cask_apps.add(it["name"].lower() + ".app")  # pkg-installed casks (e.g. Tailscale)
    bundles = []
    for p in _app_bundles():
        if os.path.basename(p).lower() in cask_apps:
            continue  # already listed as a Homebrew app
        meta = os.path.join(p, "Wrapper", "iTunesMetadata.plist")
        if os.path.exists(meta):  # iPhone/iPad app from the App Store
            try:
                with open(meta, "rb") as f:
                    m = plistlib.load(f)
                pl = {"CFBundleShortVersionString": m.get("bundleShortVersionString"),
                      "CFBundleIdentifier": m.get("softwareVersionBundleId", ""), "_adam": str(m.get("itemId") or "")}
                bundles.append((p, pl, pl["CFBundleIdentifier"], True))
            except Exception:
                pass
            continue
        try:
            with open(os.path.join(p, "Contents", "Info.plist"), "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        bid = pl.get("CFBundleIdentifier", "")
        if bid in SELF_BUNDLES:
            continue  # Zeke itself and apps listed in config.json "ignore_apps"
        if bid.startswith("com.apple.") and not os.path.exists(os.path.join(p, "Contents", "_MASReceipt")):
            continue  # Safari etc. — updates with macOS
        bundles.append((p, pl, bid, os.path.exists(os.path.join(p, "Contents", "_MASReceipt"))))
    errors = []
    try:
        mas = _mas_latest([(b[2], b[1].get("_adam") or _adam_id(b[0])) for b in bundles if b[3]])
    except Exception as e:
        mas, errors = None, errors + ["App Store lookup failed: %s" % e]
    try:
        catalog = _cask_catalog()
    except Exception as e:
        catalog, errors = None, errors + ["Homebrew catalog download failed: %s" % e]
    items = []
    for p, pl, bid, is_mas in bundles:
        name = os.path.basename(p)[:-4]
        inst = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
        installer = None
        inner = inner_version(bid)
        if inner and vtuple(inner) and vtuple(inst) and vtuple(inner) > vtuple(inst):
            installer, inst = inst, inner
        base = dict(name=name, installed=inst, path=p, bundle_id=bid)
        if installer:
            base["installer_version"] = installer
        if is_mas:
            lat = (mas or {}).get(bid)
            if mas is None:
                st, note = "unknown", "App Store lookup failed"
            elif not lat:
                st, note = "unknown", "Apple doesn't publish this listing — check App Store"
            else:
                st, note = compare_app(inst, lat[0])
            items.append(item("app:mas:" + bid, source="App Store apps", latest=lat[0] if lat else None,
                              status=st, action="open", note=note, track_id=lat[1] if lat else None,
                              **base))
            continue
        m = (catalog or {}).get(os.path.basename(p).lower())
        if catalog is None:
            st, lat, note = "unknown", None, "catalog unavailable"
        elif not m:
            st, lat, note = "unknown", None, "no version source — use the app's own updater"
        elif m[1] == "latest":
            st, lat, note = "unknown", None, "cask %s has no fixed version" % m[0]
        else:
            lat = m[1].split(",")[0]
            st, why = compare_app(inst, m[1])
            note = "via Homebrew catalog (%s)" % m[0] + ("; " + why if why else "")
        if installer:
            note = "app %s (updates itself); installer %s is older — get a new installer from %s for the " \
                   "latest Electron security fixes" % (inst, installer, INNER_VERSIONS[bid][2]) + \
                   ("; " + note if note else "")
        blk = self_update_blocker(p, bid) if bid else None
        if blk:
            note = (note + "; " if note else "") + "can't update itself: " + blk["why"]
        items.append(item("app:other:" + bid if bid else "app:other:" + name, source="Other apps",
                          latest=lat, status=st, action="open", note=note, self_update_blocked=blk, **base))
    if errors:
        for it in items:
            it.setdefault("collector_errors", errors)
    return items, errors


def col_macos():
    _, ver, _ = capture(["sw_vers", "-productVersion"])
    ver = ver.strip()
    code, out, err = capture(["softwareupdate", "-l"], timeout=90)
    text = out + err
    if code != 0 and "No new software available" not in text:
        raise RuntimeError(text.strip()[-300:] or "softwareupdate failed")
    items = []
    titles = re.findall(r"Title: ([^,]+), Version: ([^,]+),.*?Action: ?(\w*)", text)
    mac = [t for t in titles if t[0].startswith("macOS")]
    if mac:
        items.append(item("macos", "macOS", "macOS", ver, mac[0][1], "outdated", "open",
                          "needs restart" if mac[0][2] == "restart" else ""))
    else:
        items.append(item("macos", "macOS", "macOS", ver, ver, "current", "open", ""))
    for t in titles:
        if not t[0].startswith("macOS"):
            items.append(item("macos:" + t[0], t[0], "macOS", None, t[1], "outdated", "open", ""))
    return items


# ---------------------------------------------------------------- runs
class Busy(Exception):
    pass


class Cancelled(BaseException):
    """SIGTERM from the dashboard's Stop button. BaseException so `except Exception` handlers don't swallow it."""


class Run:
    def __init__(self, kind, trigger, detail=""):
        self.lockf = open(LOCKFILE, "w")
        try:
            fcntl.flock(self.lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy()
        self.id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + kind
        self.logpath = os.path.join(LOGS, self.id + ".log")
        self.log = open(self.logpath, "a", buffering=1)
        self.rec = dict(id=self.id, kind=kind, trigger=trigger, detail=detail, started=now_iso(),
                        ended=None, result="running", steps=[], pid=os.getpid(), log=self.logpath)
        self.save()
        write_json(CURRENT, self.rec)
        self.say("##### %s  %s (%s) %s" % (self.rec["started"], kind, trigger, detail))

    def save(self):
        write_json(os.path.join(RUNS, self.id + ".json"), self.rec)

    def say(self, msg):
        self.log.write(msg + "\n")

    def step(self, name, argv, timeout=STEP_TIMEOUT):
        self.say("\n== %s\n$ %s" % (name, " ".join(argv)))
        st = dict(name=name, argv=argv, exit=None, seconds=None, status="running")
        self.rec["steps"].append(st)
        self.save()
        t0 = time.time()
        tail = []
        try:
            p = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, errors="replace",
                                 start_new_session=True)
            timer = threading.Timer(timeout, lambda: os.killpg(p.pid, 9))  # whole process group
            timer.start()
            try:
                for line in p.stdout:
                    self.log.write(line)
                    tail.append(line.lower())
                    tail = tail[-200:]
                p.wait()
            except Cancelled:
                timer.cancel()
                try:
                    os.killpg(p.pid, 15)
                except OSError:
                    pass
                raise
            timer.cancel()
            code = p.returncode
            if code < 0 and time.time() - t0 >= timeout - 1:
                self.say("!! timed out after %ss" % timeout)
                code = 124
        except FileNotFoundError:
            self.say("!! not found: %s" % argv[0])
            code = 127
        st["exit"], st["seconds"] = code, round(time.time() - t0, 1)
        joined = "".join(tail)
        if code == 0:
            st["status"] = "ok"
        elif any(h in joined for h in PASSWORD_HINTS):
            st["status"] = "needs-password"
        else:
            st["status"] = "failed"
        self.say("-> %s (exit %s, %ss)" % (st["status"], code, st["seconds"]))
        self.save()
        return code

    def begin(self, name):
        """A step that isn't a single command (e.g. waiting on an app). Update st['name'] for live progress."""
        self.say("\n== %s" % name)
        st = dict(name=name, argv=[], exit=None, seconds=None, status="running", _t0=time.time())
        self.rec["steps"].append(st)
        self.save()
        return st

    def end(self, st, status, note=""):
        st["status"], st["seconds"] = status, round(time.time() - st.pop("_t0", time.time()), 1)
        st["exit"] = 0 if status == "ok" else 1
        if note:
            st["note"] = note
        self.say("-> %s%s" % (status, (" — " + note) if note else ""))
        self.save()

    def finish(self, result=None):
        bad = [s for s in self.rec["steps"] if s["status"] not in ("ok", "no-change")]
        if result is None:
            result = "ok" if not bad else ("failed" if len(bad) == len(self.rec["steps"]) else "partial")
        self.rec.update(ended=now_iso(), result=result)
        self.say("\n##### done %s — %s" % (self.rec["ended"], result))
        self.save()
        try:
            os.remove(CURRENT)
        except FileNotFoundError:
            pass
        self.log.close()
        return result


def do_scan(run, refresh=True, deep=False):
    """Collect everything into inventory.json, then run security checks into security.json.
    Returns (inventory, security, new_urgent_findings)."""
    if refresh and BREW:
        run.step("Refresh Homebrew index", [BREW, "update"])
    t0 = time.time()
    collectors = {"macos": col_macos, "clis": col_clis}
    if BREW:
        collectors["brew"] = col_brew
    for key in NPMS:
        collectors["npm-" + key] = (lambda k: (lambda: col_npm(k)))(key)
    if GEM:
        collectors["gem"] = col_gem
    if PIP:
        collectors["pip"] = col_pip
    if UV:
        collectors["uv-tools"] = col_uv_tools
    status_brew_ok = lambda: status.get("brew", {}).get("ok", False)
    results, status = {}, {}
    with concurrent.futures.ThreadPoolExecutor(10) as ex:
        futs = {ex.submit(fn): k for k, fn in collectors.items()}
        # small feeds (KEV, SOFA) refresh in parallel when stale; 8 s budget, never blocks the scan
        feed_futs = [ex.submit(feeds.refresh, n, 8) for n in feeds.SMALL]
        for f in concurrent.futures.as_completed(futs):
            k = futs[f]
            try:
                results[k] = f.result()
                status[k] = {"ok": True, "count": len(results[k])}
            except Exception as e:
                results[k] = []
                status[k] = {"ok": False, "error": str(e)[:400]}
            run.say("collector %-11s %s" % (k, "ok (%d)" % status[k]["count"] if status[k]["ok"]
                                            else "FAILED: " + status[k]["error"]))
        for n, ff in zip(feeds.SMALL, feed_futs):
            run.say("feed %-16s %s" % (n, ff.result()))
    prev = read_json(INVENTORY, {}) or {}
    brew_items = results.get("brew", [])
    if not status_brew_ok():  # keep cask-app de-duplication working from the previous scan
        brew_items = [i for i in prev.get("items", []) if i["id"].startswith("brew:cask:")]
    try:
        apps, errs = col_apps(brew_items)
        status["apps"] = {"ok": not errs, "count": len(apps), "error": "; ".join(errs) if errs else None}
    except Exception as e:
        apps, status["apps"] = [], {"ok": False, "error": str(e)[:400]}
    run.say("collector %-11s %s" % ("apps", status["apps"]))
    items = []
    for k in collectors:
        items += results[k]
    items += apps
    for it in items:
        it.pop("apps", None)
    # A failed collector's previous items stay visible but as unknown — never "current".
    src_of = {"brew": ("Homebrew formulae", "Homebrew apps"), "gem": ("Ruby gems",), "pip": ("Python packages",),
              "uv-tools": ("uv tools",), "clis": ("CLI tools",), "macos": ("macOS",),
              "apps": ("App Store apps", "Other apps")}
    src_of.update({"npm-" + k: (v[0],) for k, v in NPMS.items()})
    for k, st in status.items():
        if not st["ok"] and st.get("count") is None:
            for old in prev.get("items", []):
                if old["source"] in src_of[k]:
                    old.update(status="unknown", note="last scan failed: " + st["error"][:120])
                    items.append(old)
    hl = checks.holds()
    for it in items:
        h = hl.get(it["id"])
        if h:
            it["hold"] = h
        if it.get("pinned"):
            it["hold"] = {"mode": "hold", "reason": "pinned with brew pin", "pinned": True}
        a, b = vtuple(it.get("installed")), vtuple(it.get("latest"))
        if it["status"] == "outdated" and a and b and a[0] != b[0]:
            it["major"] = True
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("current", "outdated", "unknown")}
    inv = dict(scanned=now_iso(), seconds=round(time.time() - t0, 1), run=run.id, collectors=status,
               counts=counts, items=items)
    write_json(INVENTORY, inv)
    run.say("scan: %d items — %s" % (len(items), counts))
    sec, new_urgent = None, []
    try:
        ctx = {"items": items, "brew_info": BREW_INFO if status_brew_ok() else None, "settings": settings(),
               "brew": BREW}
        sec, new_urgent = checks.run_checks(ctx, deep=deep, log=run.say)
        run.say("security: %s" % sec["summary"])
    except Exception as e:
        run.say("!! security checks failed: %r" % e)
        run.rec["steps"].append(dict(name="Security checks", argv=[], exit=1, seconds=0, status="failed"))
    for k, st in status.items():
        if not st["ok"]:
            run.rec["steps"].append(dict(name="Collector " + k, argv=[], exit=1, seconds=0,
                                         status="failed"))
    run.save()
    return inv, sec, new_urgent


def _safe(name):
    if not NAME_RE.match(name or ""):
        raise ValueError("refusing unsafe package name: %r" % name)
    return name


def action_for(it):
    """Engine-owned command table. Returns list of (name, argv) or None."""
    if not it or it.get("action") != "update":
        return None
    i, src = it["id"], it["id"].split(":")
    try:
        if src[0] == "brew" and src[1] == "formula":
            return [("brew upgrade " + src[2], [BREW, "upgrade", "--formula", "--", _safe(src[2])])]
        if src[0] == "brew" and src[1] == "cask":
            return [("brew upgrade --cask " + src[2], [BREW, "upgrade", "--cask", "--greedy", "--", _safe(src[2])])]
        if src[0] == "npm":
            key, pkg = src[1], ":".join(src[2:])
            if key not in NPMS:
                return None
            return [("npm %s: %s@latest" % (key, pkg), npm_argv(key, "install", "--", _safe(pkg) + "@latest"))]
        if src[0] == "gem" and GEM:
            return [("gem update " + src[1], [GEM, "update", "--", _safe(src[1])])]
        if src[0] == "pip" and PIP:
            return [("pip install -U " + src[1], [PIP, "install", "--upgrade", "--break-system-packages",
                                                   "--disable-pip-version-check", "--", _safe(src[1])])]
        if src[0] == "uv" and UV:
            return [("uv tool upgrade " + src[1], [UV, "tool", "upgrade", _safe(src[1])])]
    except ValueError:
        return None
    if i in CLIS:
        name, binary, args, _ = CLIS[i]
        return [("%s %s" % (os.path.basename(binary), " ".join(args)), [binary] + args)]
    return None


def notify(title, msg):
    script = 'display notification %s with title %s' % (json.dumps(msg), json.dumps(title))
    capture(["osascript", "-e", script], timeout=15)


def summary(inv):
    c = inv["counts"]
    s = "%d updates available" % c["outdated"] if c["outdated"] else "Everything is up to date"
    return s + (" · %d can't tell" % c["unknown"] if c["unknown"] else "")


def notify_security(new_urgent):
    if not new_urgent or not settings().get("notify_security"):
        return
    if len(new_urgent) == 1:
        notify("Zeke — security", new_urgent[0]["title"][:120])
    else:
        notify("Zeke — security", "%d new urgent security items: %s" % (
            len(new_urgent), ", ".join(f.get("subject") or f["title"] for f in new_urgent)[:110]))


# ---------------------------------------------------------------- plan / holds
GROUP_ORDER = ["brew:formula", "brew:cask"] + ["npm:" + k for k in NPMS] + ["gem", "uv", "cli"]


def plan(inv=None, sec=None):
    """What update-all will do, from the last scan. Security fixes first, holds excluded."""
    inv = inv or read_json(INVENTORY, {}) or {}
    sec = sec or read_json(paths.SECURITY, {}) or {}
    hl = checks.holds()
    secfix = {}
    for f in sec.get("findings", []):
        if f.get("state") == "open" and f["fix"].get("type") == "update" and f.get("item_id"):
            secfix.setdefault(f["item_id"], f)
    included, held, skipped, majors = [], [], [], []
    for it in inv.get("items", []):
        if it.get("action") != "update" or not it.get("auto"):
            continue
        blind = (it["id"] in CLIS and not CLIS[it["id"]][3]) or it["id"].startswith("uv:")
        if it["status"] != "outdated" and not blind:
            continue
        h = hl.get(it["id"])
        if it.get("pinned") or (h and h.get("mode") == "hold"):
            held.append(it["id"])
            continue
        if h and h.get("mode") == "skip" and h.get("version") == it.get("latest"):
            skipped.append(it["id"])
            continue
        if it.get("major"):
            majors.append(it["id"])
        included.append(it)
    sec_first = [i for i in included if i["id"] in secfix]
    rest = [i for i in included if i["id"] not in secfix]
    return {"security_first": [i["id"] for i in sec_first], "others": [i["id"] for i in rest],
            "majors": majors, "held": held, "skipped": skipped,
            "names": {i["id"]: i["name"] for i in included}, "_items": sec_first + rest}


def _group(it):
    p = it["id"].split(":")
    return ":".join(p[:2]) if p[0] in ("brew", "npm") else p[0]


def plan_steps(pl):
    """Batch explicit names per tool. Security group of each tool runs before the rest."""
    steps = []
    for phase, ids in (("security", set(pl["security_first"])), ("rest", set(pl["others"]))):
        items = [i for i in pl["_items"] if i["id"] in ids]
        for g in GROUP_ORDER:
            names = [i for i in items if _group(i) == g]
            if not names:
                continue
            tag = " (security fixes)" if phase == "security" else ""
            try:
                if g == "brew:formula":
                    steps.append(("Homebrew formulae%s" % tag, [BREW, "upgrade", "--formula", "--"] +
                                  [_safe(i["id"].split(":")[2]) for i in names]))
                elif g == "brew:cask":
                    steps.append(("Homebrew apps%s" % tag, [BREW, "upgrade", "--cask", "--greedy", "--"] +
                                  [_safe(i["id"].split(":")[2]) for i in names]))
                elif g.startswith("npm:"):
                    key = g.split(":")[1]
                    steps.append(("%s%s" % (NPMS[key][0], tag), npm_argv(key, "install", "--") +
                                  [_safe(":".join(i["id"].split(":")[2:])) + "@latest" for i in names]))
                elif g == "gem":
                    steps.append(("Ruby gems%s" % tag, [GEM, "update", "--"] + [_safe(i["name"]) for i in names]))
                else:
                    for i in names:
                        steps += action_for(i) or []
            except ValueError:
                continue
    return steps


def cmd_plan():
    pl = plan()
    pl.pop("_items")
    print(json.dumps(pl, indent=1))
    return 0


def cmd_hold(id, mode, version=None, reason=""):
    inv = read_json(INVENTORY, {}) or {}
    it = next((i for i in inv.get("items", []) if i["id"] == id), None)
    if not it or not (it.get("action") == "update" or app_updatable(it)) or mode not in ("hold", "skip", "none"):
        return 2
    hl = checks.holds()
    if mode == "none":
        hl.pop(id, None)
    elif mode == "skip":
        if version != it.get("latest"):
            return 2
        hl[id] = {"mode": "skip", "version": version, "created": datetime.date.today().isoformat()}
    else:
        hl[id] = {"mode": "hold", "reason": (reason or "")[:200], "created": datetime.date.today().isoformat()}
    checks._write(paths.HOLDS, hl)
    _refresh_states()
    return 0


def cmd_mute(fid, days=None):
    sec = read_json(paths.SECURITY, {}) or {}
    if not any(f["id"] == fid for f in sec.get("findings", [])):
        return 2
    st = read_json(paths.SEC_STATE, {}) or {}
    mutes = st.setdefault("mutes", {})
    if days == "off":
        mutes.pop(fid, None)
    else:
        mutes[fid] = {"until": None if days is None else time.time() + int(days) * 86400,
                      "created": datetime.date.today().isoformat()}
    checks._write(paths.SEC_STATE, st)
    _refresh_states()
    return 0


def _refresh_states():
    """Re-apply holds/mutes to the current findings and inventory without rescanning."""
    inv = read_json(INVENTORY, {}) or {}
    hl = checks.holds()
    for it in inv.get("items", []):
        it.pop("hold", None)
        if it["id"] in hl:
            it["hold"] = hl[it["id"]]
        if it.get("pinned"):
            it["hold"] = {"mode": "hold", "reason": "pinned with brew pin", "pinned": True}
    if inv:
        write_json(INVENTORY, inv)
    sec = read_json(paths.SECURITY, {}) or {}
    if not sec:
        return
    mutes = (read_json(paths.SEC_STATE, {}) or {}).get("mutes", {})
    now = time.time()
    for f in sec["findings"]:
        m = mutes.get(f["id"])
        if m and (m.get("until") is None or m["until"] > now):
            f["state"] = "muted"
        elif f.get("item_id") in hl and f["fix"].get("type") == "update":
            f["state"] = "held"
        else:
            f["state"] = "open"
        f["urgent"] = checks.is_urgent(f) or (f["state"] == "held" and bool(f.get("exploited")))
    open_f = [f for f in sec["findings"] if f["state"] == "open"]
    sec["summary"].update(
        urgent=sum(1 for f in sec["findings"] if f["urgent"]),
        review=sum(1 for f in open_f if f["severity"] in ("critical", "high", "medium")),
        noted=sum(1 for f in open_f if f["severity"] in ("low", "info")),
        muted=sum(1 for f in sec["findings"] if f["state"] == "muted"),
        held=sum(1 for f in sec["findings"] if f["state"] == "held"))
    sec["rev"] = int(sec.get("rev", 0)) + 1
    checks._write(paths.SECURITY, sec)


# ---------------------------------------------------------------- commands
def cmd_scan(trigger, do_notify, deep=False):
    if trigger == "weekly":
        if not settings()["weekly_check"]:
            return 0
        deep = True
    run = Run("scan", trigger, "deep check" if deep else "")
    try:
        inv, sec, new_urgent = do_scan(run, deep=deep)
        res = run.finish()
    except Exception as e:
        run.say("!! " + repr(e))
        run.finish("failed")
        raise
    notify_security(new_urgent)
    if do_notify:
        s = summary(inv)
        if sec and sec["summary"]["review"]:
            s += " · %d security item%s to review" % (sec["summary"]["review"], "s" if sec["summary"]["review"] != 1 else "")
        notify("Zeke", s)
    return 0 if res == "ok" else 1


def cmd_update(ids, trigger):
    inv = read_json(INVENTORY, {}) or {}
    by_id = {i["id"]: i for i in inv.get("items", [])}
    hl = checks.holds()
    steps = []
    apps = []
    for i in ids:
        it = by_id.get(i)
        acts = action_for(it) if it else None
        if not acts and not app_updatable(it):
            print("refusing unknown or non-updatable id: %s" % i, file=sys.stderr)
            return 2
        if (hl.get(i) or {}).get("mode") == "hold" or it.get("pinned"):
            print("refusing held item: %s (release the hold first)" % i, file=sys.stderr)
            return 2
        if acts:
            steps += acts
        else:
            apps.append(it)
    names = ", ".join(by_id[i]["name"] for i in ids)
    run = Run("update", trigger, names)
    new_urgent = []
    try:
        if BREW and any(i.startswith("brew:") for i in ids):
            run.step("Refresh Homebrew index", [BREW, "update"])
        for name, argv in steps:
            run.step(name, argv)
        if apps:
            run_app_updates(run, apps)
        n = len(run.rec["steps"])
        inv, sec, new_urgent = do_scan(run, refresh=False)
        run.rec["steps"] = run.rec["steps"][:n] + [s for s in run.rec["steps"][n:] if s["status"] != "ok"]
        res = run.finish()
    except Exception as e:
        run.say("!! " + repr(e))
        res = run.finish("failed")
    notify_security(new_urgent)
    notify("Zeke", "Updated %s — %s" % (names[:60], res))
    return 0 if res == "ok" else 1


def cmd_update_all(trigger):
    run = Run("update-all", trigger)
    new_urgent = []
    try:
        # fresh inventory + checks first, so the plan is based on current data
        inv, sec, nu = do_scan(run, refresh=True)
        new_urgent += nu
        pl = plan(inv, sec)
        run.rec["plan"] = {k: v for k, v in pl.items() if k != "_items"}
        run.rec["steps"] = [s for s in run.rec["steps"] if s["status"] != "ok"]  # keep only failed pre-scan steps
        run.say("plan: %d security-first, %d others, %d held, %d skipped" % (
            len(pl["security_first"]), len(pl["others"]), len(pl["held"]), len(pl["skipped"])))
        for name, argv in plan_steps(pl):
            run.step(name, argv)
        if BREW:
            run.step("Homebrew cleanup", [BREW, "cleanup"])
        if "cli:uv" in CLIS and "cli:uv" not in pl["security_first"] + pl["others"]:
            run.step("uv", [CLIS["cli:uv"][1]] + list(CLIS["cli:uv"][2]))
        n = len(run.rec["steps"])
        inv, sec, nu = do_scan(run, refresh=False)
        new_urgent += nu
        run.rec["steps"] = run.rec["steps"][:n] + [s for s in run.rec["steps"][n:] if s["status"] != "ok"]
        res = run.finish()
        bad = [s["name"] for s in run.rec["steps"] if s["status"] != "ok"]
        msg = "Update all: %s" % res + (" (%s)" % ", ".join(bad)[:80] if bad else "") + ". " + summary(inv)
    except Exception as e:
        run.say("!! " + repr(e))
        res = run.finish("failed")
        msg = "Update all failed: %s" % e
    notify_security(new_urgent)
    notify("Zeke", msg)
    return 0 if res in ("ok", "partial") else 3


# ---------------------------------------------------------------- apps that update themselves
# Many apps (Electron/Squirrel, electron-updater, Sparkle) only update while open and install on quit.
# "Open & update": open the app in the background, wait for its updater to download, quit it so the
# update installs, then confirm the version on disk changed. Apps that were already open are left open.
APP_START_WAIT = 300      # no updater activity at all for this long -> try quit-to-install anyway
APP_MAX_DOWNLOAD = 900    # cap for a download that keeps going
APP_QUIET = 25            # activity must be quiet this long before we treat the download as finished
APP_HANDOFF_WAIT = 120    # Squirrel apps: after the download, wait this long for Squirrel to stage it
APP_QUIT_TIMEOUT = 60
APP_FINISH_WAIT = 300
UPDATER_RE = re.compile(r"ShipIt|Autoupdate|Updater\.app|/Updater |Installer|Squirrel|update", re.I)


OPENED_BY_US = set()


def app_updatable(it):
    p = (it or {}).get("path") or ""
    return bool(it and it.get("source") == "Other apps" and it.get("bundle_id")
                and it["bundle_id"] not in SELF_BUNDLES and os.path.isdir(p)
                and (p.startswith("/Applications/") or p.startswith(os.path.join(HOME, "Applications") + "/")))


def self_update_blocker(path, bid):
    """Why the app can't replace itself (Squirrel/Sparkle need write access), or None."""
    import pwd
    import stat as _st
    # Only apps that replace their own bundle (Squirrel, electron-updater, Sparkle). Chrome, Edge, Zoom, Adobe…
    # are root-owned on purpose and update through privileged helpers.
    if not set(_app_kind(path)) & {"Squirrel", "electron-updater", "Sparkle"}:
        return None
    me = pwd.getpwuid(os.getuid()).pw_name
    groups = set(os.getgroups())

    def writable(p):
        # Ownership/mode bits, not os.access(): macOS App Management makes os.access() say "no" for
        # other apps' bundles even when the app's own updater is allowed to replace itself.
        try:
            m = os.stat(p)
        except OSError:
            return True
        if m.st_uid == os.getuid():
            return bool(m.st_mode & _st.S_IWUSR)
        if m.st_gid in groups and m.st_mode & _st.S_IWGRP:
            return True
        return bool(m.st_mode & _st.S_IWOTH)

    bad = []
    if os.path.exists(path) and not writable(path):
        bad.append(path)
    cache = os.path.join(HOME, "Library", "Caches", bid + ".ShipIt")
    if os.path.isdir(cache) and not writable(cache):
        bad.append(cache)
    if not bad:
        return None
    owner = {}
    for b in bad:
        try:
            owner[b] = pwd.getpwuid(os.stat(b).st_uid).pw_name
        except (KeyError, OSError):
            owner[b] = "another user"
    import shlex as _sh
    cmd = "sudo chown -R %s:staff %s" % (me, " ".join(_sh.quote(b) for b in bad))
    return {"why": "owned by %s, so the app can't update itself" % ", ".join(sorted(set(owner.values()))),
            "paths": bad, "command": cmd}


def _app_version(path):
    try:
        with open(os.path.join(path, "Contents", "Info.plist"), "rb") as f:
            pl = plistlib.load(f)
        v = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
        inner = inner_version(pl.get("CFBundleIdentifier", ""))
        if inner and vtuple(inner) and vtuple(v) and vtuple(inner) > vtuple(v):
            return inner
        return v
    except Exception:
        return None


def _app_kind(path):
    fw = os.path.join(path, "Contents", "Frameworks")
    kinds = []
    if os.path.isdir(os.path.join(fw, "Squirrel.framework")):
        kinds.append("Squirrel")
    if os.path.exists(os.path.join(path, "Contents", "Resources", "app-update.yml")):
        kinds.append("electron-updater")
    if os.path.isdir(os.path.join(fw, "Sparkle.framework")):
        kinds.append("Sparkle")
    return kinds or ["own updater"]


def _watch_dirs(path, bid):
    caches = os.path.join(HOME, "Library", "Caches")
    dirs = [os.path.join(caches, bid + ".ShipIt"), os.path.join(caches, bid, "org.sparkle-project.Sparkle")]
    if bid in INNER_VERSIONS:
        dirs.append(INNER_VERSIONS[bid][0])
    try:
        with open(os.path.join(path, "Contents", "Resources", "app-update.yml")) as f:
            m = re.search(r"^updaterCacheDirName:\s*(\S+)", f.read(), re.M)
        if m and re.match(r"^[\w.-]+$", m.group(1)):
            dirs.append(os.path.join(caches, m.group(1)))
    except OSError:
        pass
    return dirs


def _newest_mtime(dirs):
    newest = 0
    for d in dirs:
        for root, _, files in os.walk(d):
            for fn in files:
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(root, fn)))
                except OSError:
                    pass
    return newest


def _squirrel_staged_since(bid, t0):
    """Squirrel writes ShipItState.plist (and an update.* folder) once an update is staged to install on quit."""
    d = os.path.join(HOME, "Library", "Caches", bid + ".ShipIt")
    try:
        for fn in os.listdir(d):
            if (fn == "ShipItState.plist" or fn.startswith("update.")) and os.path.getmtime(os.path.join(d, fn)) > t0:
                return True
    except OSError:
        pass
    return False


def _updater_procs(path, bid):
    code, out, _ = capture(["ps", "-axo", "pid=,command="], timeout=10)
    hits = []
    me = os.getpid()
    main_exe = os.path.join(path, "Contents", "MacOS") + "/"
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) < 2 or int(parts[0]) == me:
            continue
        cmd = parts[1]
        if (path in cmd or bid in cmd) and UPDATER_RE.search(cmd) and not cmd.startswith(main_exe) \
                and "Helper" not in cmd and "engine.py" not in cmd:
            hits.append(cmd[:120])
    return hits


def _running(bid):
    return capture([UC_APPS, "running", bid], timeout=15)[0] == 0


def app_update_one(run, it):
    name, path, bid = it["name"], it["path"], it["bundle_id"]
    blk = self_update_blocker(path, bid)
    if blk:
        st = run.begin(name)
        run.say("%s: %s (%s)" % (name, blk["why"], ", ".join(blk["paths"])))
        run.end(st, "needs-fix", "%s is %s. Not opened. Fix it once in Terminal (needs your admin password), then "
                                 "try again:  %s" % (name, blk["why"], blk["command"]))
        return "needs-fix"
    before = _app_version(path)
    kinds = _app_kind(path)
    dirs = _watch_dirs(path, bid)
    was_running = _running(bid)
    run.say("%s %s — updater: %s — staging: %s" % (name, before, ", ".join(kinds), ", ".join(dirs)))
    st = run.begin("%s: opening" % name)
    t0 = time.time()
    opened = False
    if was_running:
        run.say("%s is already open — Zeke will watch but not close it" % name)
    else:
        code, _, err = capture([UC_APPS, "open", path], timeout=60)
        if code != 0:
            run.end(st, "failed", "couldn't open %s: %s" % (name, err.strip()[:120]))
            return "failed"
        opened = True
        OPENED_BY_US.add(bid)
    # phase 1: wait for the app's updater to start and finish downloading
    st["name"] = "%s: waiting for its updater" % name
    run.save()
    last_activity, saw_activity, downloaded = 0, False, False
    while True:
        time.sleep(5)
        now = time.time()
        v = _app_version(path)
        if v and v != before:
            run.say("version changed on disk: %s -> %s" % (before, v))
            break
        procs = _updater_procs(path, bid)
        mt = _newest_mtime(dirs)
        if procs or mt > t0:
            if not saw_activity:
                run.say("update activity detected (%s)" % ("; ".join(procs[:2]) or "files staged"))
                st["name"] = "%s: downloading update" % name
                run.save()
            saw_activity = True
            last_activity = max(last_activity, mt if mt > t0 else 0, now if procs else 0)
        if "Squirrel" in kinds and _squirrel_staged_since(bid, t0):
            run.say("update staged by Squirrel — ready to install on quit")
            time.sleep(5)
            break
        quiet = now - last_activity
        if saw_activity and not procs and (
                ("Squirrel" not in kinds and quiet > APP_QUIET) or quiet > APP_HANDOFF_WAIT):
            run.say("download looks finished" if "Squirrel" not in kinds else
                    "downloaded, but Squirrel didn't stage it within %d s — closing anyway" % APP_HANDOFF_WAIT)
            downloaded = True
            break
        if not saw_activity and now - t0 > APP_START_WAIT:
            run.say("no updater activity after %d s — will quit so any pending update can install" % APP_START_WAIT)
            break
        if now - t0 > APP_MAX_DOWNLOAD:
            run.say("still busy after %d s — moving on" % APP_MAX_DOWNLOAD)
            break
        if opened and not _running(bid):
            run.say("%s quit on its own (often a restart-to-update)" % name)
            break
    # phase 2: quit so the update installs (only if we opened it), then wait for the result
    if opened and _running(bid):
        st["name"] = "%s: closing to install" % name
        run.save()
        code, _, _ = capture([UC_APPS, "quit", bid, str(APP_QUIT_TIMEOUT)], timeout=APP_QUIT_TIMEOUT + 15)
        if code == 2:
            run.say("%s didn't quit — it may be showing a dialog (save changes / install update?)" % name)
    st["name"] = "%s: installing" % name
    run.save()
    end = time.time() + APP_FINISH_WAIT
    after = _app_version(path)
    while time.time() < end and after == before:
        time.sleep(5)
        after = _app_version(path)
        if after == before and not _updater_procs(path, bid) and time.time() > end - APP_FINISH_WAIT + 30:
            break  # nothing installing after 30 s
    # some updaters relaunch the app after installing; close it again if we opened it
    if opened:
        time.sleep(3)
        if _running(bid):
            capture([UC_APPS, "quit", bid, str(APP_QUIT_TIMEOUT)], timeout=APP_QUIT_TIMEOUT + 15)
    still_open = _running(bid)
    OPENED_BY_US.discard(bid)
    st["name"] = name
    if after and after != before:
        run.end(st, "ok", "updated %s → %s%s" % (before, after, " (left open)" if still_open else ""))
        return "ok"
    if was_running:
        run.end(st, "no-change", "it was already open, so it was left running — quit %s yourself to finish any "
                                 "downloaded update" % name)
    elif still_open:
        run.end(st, "no-change", "%s is still open — it may be asking you something (update prompt or "
                                 "save dialog)" % name)
    elif downloaded:
        run.end(st, "no-change", "%s downloaded the update but didn't install it on quit — it waits for you to "
                                 "click its own “Restart to update” / “Install” button. Open %s and click it."
                % (name, name))
    else:
        run.end(st, "no-change", "no update installed (still %s). It may need you to click Update inside the app, "
                                 "or it updates on its own schedule" % before)
    return "no-change"


def run_app_updates(run, apps):
    results = {}
    for it in apps:
        try:
            results[it["id"]] = app_update_one(run, it)
        except Exception as e:
            run.say("!! %s: %r" % (it["name"], e))
            results[it["id"]] = "failed"
    return results


def cmd_feeds(force=False):
    lf = open(FEEDS_LOCK, "w")
    try:
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("busy: feeds are already refreshing", file=sys.stderr)
        return BUSY_EXIT
    rc = 0
    for name in list(feeds.SMALL) + list(feeds.BULK):
        r = feeds.refresh(name, timeout=180, force=force)
        print("%-14s %s" % (name, r))
        if r.startswith("error"):
            rc = 1
    return rc


def cmd_daily():
    """Run by the daily gate on a fast network: refresh feeds, then update-all if enabled."""
    cmd_feeds()
    out = {"ran": now_iso(), "daily_auto": settings()["daily_auto"]}
    if not out["daily_auto"]:
        out["result"] = "skipped (daily auto-update is off)"
        write_json(os.path.join(DATA, "last-daily.json"), out)
        return 0
    try:
        rc = cmd_update_all("daily-auto")
    except Busy:
        out["result"] = "busy"
        write_json(os.path.join(DATA, "last-daily.json"), out)
        return BUSY_EXIT
    out["result"] = "ok" if rc == 0 else "failed"
    write_json(os.path.join(DATA, "last-daily.json"), out)
    return rc


def cmd_open(id):
    inv = read_json(INVENTORY, {}) or {}
    it = next((i for i in inv.get("items", []) if i["id"] == id), None)
    if not it or it["action"] != "open":
        return 2
    if it["source"] == "macOS":
        argv = ["open", "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"]
    elif it["source"] == "App Store apps":
        argv = ["open", "macappstore://showUpdatesPage"]
    else:
        argv = ["open", it["path"]]
    return capture(argv, timeout=20)[0]


SETTINGS_PANES = {
    "filevault": "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?FileVault",
    "firewall": "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall",
    "gatekeeper": "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
    "autosec": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
    "softwareupdate": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
    "loginitems": "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
}


def open_pane(key):
    url = SETTINGS_PANES.get(key)
    return capture(["open", url], timeout=20)[0] if url else 2


def cmd_open_dashboard():
    with open(os.path.join(DATA, "token")) as f:
        tok = f.read().strip()
    return capture(["open", "http://127.0.0.1:%d/#k=" % paths.PORT + "" + tok], timeout=20)[0]


def prune():
    recs = sorted(glob.glob(os.path.join(RUNS, "*.json")))
    for p in recs[:-KEEP_RUNS]:
        rid = os.path.basename(p)[:-5]
        for q in (p, os.path.join(LOGS, rid + ".log")):
            try:
                os.remove(q)
            except OSError:
                pass


def current_run():
    cur = read_json(CURRENT)
    if not cur:
        return None
    try:
        os.kill(cur["pid"], 0)
        return read_json(os.path.join(RUNS, cur["id"] + ".json"), cur)
    except (OSError, KeyError):
        return None


def _on_term(signum, frame):
    raise Cancelled()


def main(argv):
    signal.signal(signal.SIGTERM, _on_term)
    trigger = "manual"
    if "--trigger" in argv:
        k = argv.index("--trigger")
        trigger = argv[k + 1]
        argv = argv[:k] + argv[k + 2:]
    flags = {a for a in argv if a.startswith("--")}
    argv = [a for a in argv if not a.startswith("--")]
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "scan":
            r = cmd_scan(trigger, "--notify" in flags, deep="--deep" in flags)
            prune()
            return r
        if cmd == "update" and rest:
            return cmd_update(rest, trigger)
        if cmd == "update-all":
            r = cmd_update_all(trigger)
            prune()
            return r
        if cmd == "plan":
            return cmd_plan()
        if cmd == "daily":
            r = cmd_daily()
            prune()
            return r
        if cmd == "feeds":
            return cmd_feeds(force="--force" in flags)
        if cmd == "hold" and len(rest) >= 2:
            return cmd_hold(rest[0], rest[1], rest[2] if len(rest) > 2 else None)
        if cmd == "mute" and rest:
            return cmd_mute(rest[0], rest[1] if len(rest) > 1 else None)
        if cmd == "open" and rest:
            return cmd_open(rest[0])
        if cmd == "open-dashboard":
            return cmd_open_dashboard()
        if cmd == "status":
            print(json.dumps({"version": paths.VERSION, "current": current_run(),
                              "counts": (read_json(INVENTORY, {}) or {}).get("counts")}))
            return 0
    except Busy:
        print("busy: another scan/update is running", file=sys.stderr)
        return BUSY_EXIT
    except Cancelled:
        for bid in list(OPENED_BY_US):  # close apps we opened for this run
            capture([UC_APPS, "quit", bid, "20"], timeout=30)
        cur = read_json(CURRENT)
        if cur and cur.get("pid") == os.getpid():
            rec = read_json(os.path.join(RUNS, cur["id"] + ".json"), {}) or {}
            for st in rec.get("steps", []):
                if st.get("status") == "running":
                    st["status"] = "cancelled"
            rec.update(result="cancelled", ended=now_iso())
            write_json(os.path.join(RUNS, cur["id"] + ".json"), rec)
            with open(os.path.join(LOGS, cur["id"] + ".log"), "a") as f:
                f.write("\n##### cancelled %s\n" % now_iso())
            try:
                os.remove(CURRENT)
            except OSError:
                pass
        return 130
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
