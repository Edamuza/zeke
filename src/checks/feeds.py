"""Feed cache: download, validate, atomic swap, freshness (SPEC §11)."""
import datetime
import hashlib
import io
import json
import os
import time
import zipfile

from . import net, paths

DAY = 86400
FEEDS = {
    # name: (url, refresh_after_s, stale_after_s, validator name)
    "kev": ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", DAY, 14 * DAY, "kev"),
    "sofa": ("https://sofafeed.macadmins.io/v1/macos_data_feed.json", DAY, 14 * DAY, "sofa"),
    "osv-RubyGems": ("https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip", DAY, 14 * DAY, "zip"),
    "osv-PyPI": ("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip", DAY, 14 * DAY, "zip"),
}
SMALL = ("kev", "sofa")      # fetched by interactive scans when stale
BULK = ("osv-RubyGems", "osv-PyPI")  # fetched only by `engine.py feeds`


def _file(name):
    return os.path.join(paths.FEEDS, name + (".zip" if name.startswith("osv-") else ".json"))


def meta(name):
    try:
        with open(os.path.join(paths.FEEDS, name + ".meta.json")) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_meta(name, m):
    p = os.path.join(paths.FEEDS, name + ".meta.json")
    with open(p + ".tmp", "w") as f:
        json.dump(m, f)
    os.replace(p + ".tmp", p)


def _validate(kind, body):
    if kind == "kev":
        d = json.loads(body)
        if len(d.get("vulnerabilities", [])) < 1000:
            raise ValueError("KEV list suspiciously short")
    elif kind == "sofa":
        d = json.loads(body)
        if not d.get("OSVersions"):
            raise ValueError("SOFA feed has no OSVersions")
    elif kind == "zip":
        z = zipfile.ZipFile(io.BytesIO(body))
        if z.testzip() is not None or len(z.namelist()) < 50:
            raise ValueError("zip failed integrity check")
        if sum(i.file_size for i in z.infolist()) > 1500 * 1024 * 1024:
            raise ValueError("zip expands too large")


def age(name):
    f = meta(name).get("fetched")
    return None if not f else time.time() - f


def fresh_state(name):
    """'fresh' | 'aging' | 'stale' | 'missing'"""
    url, refresh, stale, _ = FEEDS[name]
    if not os.path.exists(_file(name)):
        return "missing"
    a = age(name)
    if a is None or a > stale:
        return "stale"
    return "fresh" if a <= refresh else "aging"


def asof(name):
    f = meta(name).get("fetched")
    return datetime.datetime.fromtimestamp(f).strftime("%Y-%m-%d") if f else None


def refresh(name, timeout=60, force=False):
    """Fetch if due. Returns status string. Never raises."""
    url, ref, _, kind = FEEDS[name]
    m = meta(name)
    if not force and os.path.exists(_file(name)) and (age(name) or 1e12) < ref:
        return "fresh"
    hdr = {}
    if os.path.exists(_file(name)):
        if m.get("etag"):
            hdr["If-None-Match"] = m["etag"]
        if m.get("last_modified"):
            hdr["If-Modified-Since"] = m["last_modified"]
    try:
        code, body, h = net.get(url, timeout=timeout, headers=hdr)
        if code == 304:
            m.update(fetched=time.time(), status="not modified", error=None)
            _save_meta(name, m)
            return "not modified"
        _validate(kind, body)
        tmp = _file(name) + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, _file(name))
        m = dict(url=url, etag=h.get("ETag"), last_modified=h.get("Last-Modified"), fetched=time.time(),
                 bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), status="updated", error=None)
        _save_meta(name, m)
        if name.startswith("osv-"):
            build_osv_index(name[4:])
        return "updated"
    except Exception as e:
        m.update(status="error", error=str(e)[:300], last_attempt=time.time())
        _save_meta(name, m)
        return "error: %s" % e


def load_json(name):
    with open(_file(name)) as f:
        return json.load(f)


# ---------------------------------------------------------------- OSV index
SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def index_path(eco):
    return os.path.join(paths.FEEDS, "osv-%s.index.json" % eco)


def norm_name(eco, name):
    if eco == "PyPI":
        import re
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def build_osv_index(eco):
    z = zipfile.ZipFile(_file("osv-" + eco))
    idx = {}
    for info in z.infolist():
        if info.file_size > 5 * 1024 * 1024 or not info.filename.endswith(".json"):
            continue
        try:
            d = json.loads(z.read(info))
        except ValueError:
            continue
        if d.get("withdrawn"):
            continue
        ds = d.get("database_specific") or {}
        sev = SEV.get(str(ds.get("severity", "")).upper())
        rec_base = {
            "id": d.get("id"),
            "aliases": [a for a in d.get("aliases", []) if a.startswith(("CVE-", "GHSA-"))][:6],
            "severity": sev,
            "summary": (d.get("summary") or d.get("details") or "")[:240],
        }
        for aff in d.get("affected", []):
            pkg = aff.get("package") or {}
            if pkg.get("ecosystem") != eco or not pkg.get("name"):
                continue
            ranges = [r.get("events", []) for r in aff.get("ranges", []) if r.get("type") == "ECOSYSTEM"]
            fixed = sorted({e["fixed"] for evs in ranges for e in evs if "fixed" in e})
            rec = dict(rec_base, ranges=ranges, fixed=fixed[-3:],
                       versions=aff.get("versions", []) if not ranges else [])
            idx.setdefault(norm_name(eco, pkg["name"]), []).append(rec)
    tmp = index_path(eco) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(idx, f, separators=(",", ":"))
    os.replace(tmp, index_path(eco))
    return len(idx)


def load_index(eco):
    try:
        with open(index_path(eco)) as f:
            return json.load(f)
    except Exception:
        return None
