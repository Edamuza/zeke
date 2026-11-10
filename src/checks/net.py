"""The only HTTP client the engine uses. Every request must match a privacy-ledger entry (SPEC §10)."""
import json
import os
import time
import urllib.parse
import urllib.request

from . import paths

# id: (label, host, path prefix, what is sent, class, setting key or None, default)
LEDGER = {
    "kev": ("CISA exploited-vulnerability list", "www.cisa.gov", "/sites/default/files/feeds/",
            "nothing (fixed URL)", "Download only", None),
    "sofa": ("macOS patch feed (SOFA)", "sofafeed.macadmins.io", "/v1/",
             "nothing (fixed URL)", "Download only", None),
    "osv-bulk": ("OSV library vulnerability database", "osv-vulnerabilities.storage.googleapis.com", "/",
                 "nothing (fixed URLs)", "Download only", None),
    "cask-catalog": ("Homebrew app catalog", "formulae.brew.sh", "/api/",
                     "nothing (fixed URL)", "Download only", None),
    "cli-latest": ("Latest Claude Code / uv versions", "registry.npmjs.org", "/@anthropic-ai/",
                   "nothing (fixed URL)", "Download only", None),
    "cli-latest-pypi": ("Latest uv version", "pypi.org", "/pypi/uv/",
                        "nothing (fixed URL)", "Download only", None),
    "appstore-lookup": ("App Store versions", "itunes.apple.com", "/lookup",
                        "App Store ids of your App Store apps", "App ids, to Apple", None),
}
# Contacts made by tools themselves (shown in the UI, can't be enforced here).
VIA_TOOL = [
    ("brew-index", "Homebrew index (brew update)", "github.com / formulae.brew.sh", "nothing beyond a fetch", "Via tool", None),
    ("npm-outdated", "npm update check", "registry.npmjs.org", "names of your global npm packages", "Package names, via npm", None),
    ("pip-outdated", "pip update check", "pypi.org", "names of installed Python packages", "Package names, via pip", None),
    ("gem-outdated", "gem update check", "rubygems.org", "gem index requests", "Via tool", None),
    ("softwareupdate", "macOS Software Update", "Apple", "device and OS information", "Via tool", None),
    ("brew-vulns", "Homebrew vulnerabilities (brew vulns)", "api.osv.dev (Google)",
     "source URL and version of every installed formula", "Your formula list", "net_brew_vulns"),
]
MAX_BYTES = 120 * 1024 * 1024


class Refused(Exception):
    pass


def _entry_for(url):
    u = urllib.parse.urlsplit(url)
    for lid, e in LEDGER.items():
        if u.scheme == "https" and u.hostname == e[1] and u.path.startswith(e[2]):
            return lid
    raise Refused("no privacy-ledger entry for %s" % url)


def _record(lid, nbytes):
    p = os.path.join(paths.DATA, "ledger-state.json")
    try:
        with open(p) as f:
            st = json.load(f)
    except Exception:
        st = {}
    st[lid] = {"last_contact": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "last_bytes": nbytes}
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f)
    os.replace(tmp, p)


def get(url, timeout=60, headers=None, max_bytes=MAX_BYTES):
    """Returns (status, body bytes, response headers). 304 returns b''."""
    lid = _entry_for(url)
    req = urllib.request.Request(url, headers=dict({"User-Agent": "zeke/%s" % paths.VERSION}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("response larger than %d bytes" % max_bytes)
            _record(lid, len(body))
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            _record(lid, 0)
            return 304, b"", dict(e.headers)
        raise


def get_json(url, timeout=60):
    return json.loads(get(url, timeout=timeout)[1].decode("utf-8"))
