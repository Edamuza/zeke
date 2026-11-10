"""Security checks (SPEC §9). Stdlib only, Python 3.9.

run_checks(ctx, deep) -> security dict written to data/security.json.
Each check returns {"findings": [...], "data": {...}, "covered": n, "not_covered": n, "data_asof": str|None}
and raises to mean "can't tell" (status unknown). Checks never run sudo, delete, or change settings.
"""
import datetime
import functools
import glob
import json
import os
import plistlib
import re
import shlex
import subprocess
import time

from . import feeds, net, paths, versions

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _today():
    return datetime.date.today().isoformat()


def _run(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 127, str(e)


def _read(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _write(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def finding(id, check, kind, severity, title, detail="", item_id=None, subject=None, refs=None,
            source=None, fix=None, exploited=False, **extra):
    d = dict(id=id, check=check, kind=kind, severity=severity, title=title, detail=(detail or "")[:600],
             item_id=item_id, subject=subject, refs=refs or [], source=source or {},
             fix=fix or {"type": "none"}, exploited=bool(exploited))
    d.update(extra)
    return d


def cmd_fix(lines, needs_sudo=False, note=""):
    return {"type": "command", "command": "\n".join(lines), "needs_sudo": needs_sudo, "note": note}


# ---------------------------------------------------------------- local checks
def check_brew_lifecycle(ctx):
    info = ctx.get("brew_info")
    if not info:
        raise RuntimeError("Homebrew data unavailable this scan")
    out = []
    today = datetime.date.today()
    for kind_key, entries in (("formula", info.get("formulae", [])), ("cask", info.get("casks", []))):
        for e in entries:
            name = e.get("name") if kind_key == "formula" else e.get("token")
            if not (e.get("deprecated") or e.get("disabled")):
                continue
            item_id = "brew:%s:%s" % (kind_key, name)
            on_req = kind_key == "cask" or any(i.get("installed_on_request") for i in e.get("installed", []))
            disabled = bool(e.get("disabled"))
            ddate = e.get("disable_date")
            reason = (e.get("disable_args") or {}).get("because") or e.get("disable_reason") \
                or e.get("deprecation_reason") or "not given"
            repl_f = e.get("disable_replacement_formula") or e.get("deprecation_replacement_formula")
            repl_c = e.get("disable_replacement_cask") or e.get("deprecation_replacement_cask")
            days = None
            if ddate:
                try:
                    days = (datetime.date.fromisoformat(ddate) - today).days
                except ValueError:
                    pass
            if disabled:
                title = "%s is disabled in Homebrew" % name
                sev, label = "medium", "Disabled"
            elif ddate:
                title = "%s will be disabled on %s" % (name, datetime.date.fromisoformat(ddate).strftime("%-d %b %Y"))
                sev = "medium" if days is not None and days <= 60 else "low"
                label = "Disabled " + datetime.date.fromisoformat(ddate).strftime("%-d %b")
            else:
                title = "%s is deprecated in Homebrew" % name
                sev, label = "low", "Deprecated"
            if not on_req:
                sev = "info"
            detail = "Reason: %s. " % reason + ("Homebrew suggests %s instead. " % (repl_c or repl_f) if (repl_c or repl_f)
                                                 else "No replacement listed. ") + \
                ("It is a dependency of something else you installed." if not on_req else
                 "Disabled packages stop getting updates and can't be reinstalled.")
            fix = {"type": "manual"}
            if repl_c or repl_f:
                fix = cmd_fix(["brew install %s%s" % ("--cask " if repl_c else "", shlex.quote(repl_c or repl_f)),
                               "brew uninstall %s" % shlex.quote(name)],
                              note="Install the replacement, then remove the old one when you're ready.")
            out.append(finding("lifecycle:%s:%s" % (kind_key, name), "brew_lifecycle", "lifecycle", sev, title,
                               detail, item_id=item_id, subject=name, label=label,
                               source={"name": "Homebrew", "url": "https://formulae.brew.sh/%s/%s" %
                                       ("formula" if kind_key == "formula" else "cask", name)},
                               fix=fix))
    # untrusted taps (already detected by the collector)
    for it in ctx["items"]:
        if it["id"].startswith("brew:untrusted:"):
            m = re.search(r"tap (\S+)", it.get("note", ""))
            tap = m.group(1) if m else None
            out.append(finding("source-trust:%s" % it["name"], "brew_lifecycle", "source-trust", "info",
                               "%s comes from a tap Homebrew doesn't trust" % it["name"],
                               "Homebrew won't check or update it until you trust %s." % (tap or "its tap"),
                               item_id=it["id"], subject=it["name"], label="Untrusted tap",
                               fix=cmd_fix(["brew trust %s" % shlex.quote(tap)],
                                           note="Only if you trust this source.") if tap else {"type": "manual"}))
    return {"findings": out, "covered": len(info.get("formulae", [])) + len(info.get("casks", []))}


def check_posture(ctx):
    rows, out = [], []

    def row(key, label, state, value, sev_if_off, why):
        rows.append({"key": key, "label": label, "state": state, "value": value})
        if state == "issue":
            fix = {"type": "open", "target": key} if key in ("filevault", "gatekeeper", "firewall", "autosec") else \
                {"type": "manual", "note": "Turning SIP back on requires restarting into macOS Recovery and running "
                                           "`csrutil enable` in Terminal there."}
            out.append(finding("posture:" + key, "posture", "posture", sev_if_off, "%s is off" % label, why,
                               subject=label, label=label + " off", fix=fix))

    c, o = _run(["fdesetup", "status"])
    row("filevault", "FileVault disk encryption", "ok" if "FileVault is On" in o else
        ("issue" if "FileVault is Off" in o else "unknown"), o.strip()[:80], "high",
        "Without FileVault, anyone with your Mac can read the disk.")
    c, o = _run(["csrutil", "status"])
    row("sip", "System Integrity Protection", "ok" if "status: enabled" in o else
        ("issue" if "disabled" in o else "unknown"), o.strip()[:80], "high",
        "SIP protects system files from modification, even by admin processes.")
    c, o = _run(["spctl", "--status"])
    row("gatekeeper", "Gatekeeper", "ok" if "assessments enabled" in o else
        ("issue" if "disabled" in o else "unknown"), o.strip()[:80], "high",
        "Gatekeeper blocks unsigned and unnotarized apps.")
    c, o = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    row("firewall", "Firewall", "ok" if re.search(r"enabled|State = [12]", o) else
        ("issue" if re.search(r"disabled|State = 0", o) else "unknown"), o.strip()[:80], "medium",
        "The firewall blocks unwanted incoming connections.")
    c, o = _run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"])
    crit = re.search(r"CriticalUpdateInstall = (\d)", o)
    conf = re.search(r"ConfigDataInstall = (\d)", o)
    st = "unknown" if not (crit and conf) else ("ok" if crit.group(1) == "1" and conf.group(1) == "1" else "issue")
    row("autosec", "Automatic security updates", st,
        "on" if st == "ok" else ("off" if st == "issue" else "can't read setting"), "medium",
        "Security responses and system data files (XProtect) install automatically when this is on.")
    c, o = _run(["xprotect", "version"])
    m = re.search(r"Version:\s*(\d+)", o)
    xp = m.group(1) if m else None
    latest_xp = None
    try:
        if feeds.fresh_state("sofa") in ("fresh", "aging"):
            latest_xp = feeds.load_json("sofa").get("XProtectPlistConfigData", {}).get("com.apple.XProtect")
    except Exception:
        pass
    if xp and latest_xp and int(xp) < int(latest_xp):
        rows.append({"key": "xprotect", "label": "XProtect definitions", "state": "issue",
                     "value": "%s (latest %s)" % (xp, latest_xp)})
        out.append(finding("posture:xprotect", "posture", "posture", "low", "XProtect definitions are behind",
                           "Installed %s, Apple's latest is %s. They normally update by themselves within days."
                           % (xp, latest_xp), subject="XProtect", label="XProtect behind",
                           fix={"type": "open", "target": "softwareupdate"}))
    elif xp and latest_xp:
        rows.append({"key": "xprotect", "label": "XProtect definitions", "state": "ok", "value": xp})
    else:
        rows.append({"key": "xprotect", "label": "XProtect definitions", "state": "unknown",
                     "value": "%s — can't compare (patch feed unavailable)" % xp if xp else "can't read"})
    return {"findings": out, "data": {"rows": rows}, "covered": len(rows)}


LAUNCH_DIRS = [("user agent", os.path.expanduser("~/Library/LaunchAgents"), False),
               ("agent (all users)", "/Library/LaunchAgents", True),
               ("daemon (runs as root)", "/Library/LaunchDaemons", True)]


def check_launch_items(ctx):
    state = ctx["sec_state"]
    baseline = state.get("launch_baseline")
    first = baseline is None
    baseline = set(baseline or [])
    out, seen, unknown = [], [], 0
    for kind, d, sudo in LAUNCH_DIRS:
        for p in sorted(glob.glob(os.path.join(d, "*.plist"))):
            seen.append(p)
            try:
                with open(p, "rb") as f:
                    pl = plistlib.load(f)
            except Exception:
                unknown += 1
                continue
            prog = pl.get("Program") or (pl.get("ProgramArguments") or [None])[0]
            label = pl.get("Label") or os.path.basename(p)[:-6]
            if not prog or not str(prog).startswith("/"):
                if not prog:
                    unknown += 1
                continue
            daemon = "LaunchDaemons" in d
            if not os.path.exists(prog):
                app = re.match(r"^(/Applications/[^/]+\.app)/", prog)
                app_ok = bool(app and os.path.exists(app.group(1)))
                pre = "sudo " if sudo else ""
                dom = "system" if daemon else ("gui/%d" % os.getuid())
                cmds = ["%slaunchctl bootout %s %s" % (pre, dom, shlex.quote(p)), "%srm %s" % (pre, shlex.quote(p))]
                note = ("%s is still installed, so try reinstalling or updating it first; remove this only if you "
                        "no longer want the app." % os.path.basename(app.group(1))) if app_ok else \
                    "Leftover from an app that was removed. Safe to remove."
                out.append(finding("persistence:orphan:" + p, "launch_items", "persistence",
                                   "medium" if daemon else "low",
                                   "%s points to a missing program" % label,
                                   "%s, but %s doesn't exist. %s" % (
                                       "Runs as root at startup" if daemon else
                                       ("Runs at login" + ("" if sudo else " for your account")),
                                       prog, note),
                                   subject=label, label="Orphaned " + ("daemon" if daemon else "agent"),
                                   path=p, target=prog,
                                   fix=cmd_fix(cmds, needs_sudo=sudo)))
            elif not first and p not in baseline and not str(label).startswith(paths.LABEL_PREFIX + "."):
                out.append(finding("persistence:new:" + p, "launch_items", "persistence", "info",
                                   "New background item: %s" % label,
                                   "A %s appeared since the last check. It runs %s at %s." % (
                                       kind, prog, "startup" if daemon else "login"),
                                   subject=label, label="New launch item", path=p, target=prog, new=True,
                                   daemon=daemon, fix={"type": "manual"}))
    state["launch_baseline"] = sorted(set(seen) | (baseline if not first else set()))
    return {"findings": out, "covered": len(seen) - unknown, "not_covered": unknown}


# ---------------------------------------------------------------- feed checks
def _kev_set():
    if feeds.fresh_state("kev") in ("missing", "stale"):
        return None
    return {v["cveID"] for v in feeds.load_json("kev").get("vulnerabilities", [])}


def check_macos_patch(ctx):
    st = feeds.fresh_state("sofa")
    if st in ("missing", "stale"):
        raise RuntimeError("macOS patch feed is %s" % st)
    sofa = feeds.load_json("sofa")
    c, ver = _run(["sw_vers", "-productVersion"])
    ver = ver.strip()
    major = ver.split(".")[0]
    entry = next((o for o in sofa["OSVersions"]
                  if str(o.get("Latest", {}).get("ProductVersion", "")).split(".")[0] == major), None)
    if not entry:
        raise RuntimeError("feed has no entry for macOS %s" % major)
    latest = entry["Latest"]["ProductVersion"]
    vt = lambda v: tuple(int(x) for x in re.findall(r"\d+", v))
    data = {"running": ver, "latest": latest, "name": entry.get("OSVersion")}
    out = []
    if vt(ver) < vt(latest):
        newer = [r for r in entry.get("SecurityReleases", []) if vt(r.get("ProductVersion", "0")) > vt(ver)]
        exploited = sorted({c for r in newer for c in r.get("ActivelyExploitedCVEs", [])})
        ncve = sum(int(r.get("UniqueCVEsCount", 0) or 0) for r in newer)
        out.append(finding("patch:macos:" + latest, "macos_patch", "patch", "high" if exploited else "medium",
                           "macOS %s is behind %s" % (ver, latest),
                           "The newer release fixes %d security issues%s." % (
                               ncve, ", %d actively exploited" % len(exploited) if exploited else ""),
                           item_id="macos", subject="macOS", refs=exploited[:8], exploited=bool(exploited),
                           label="macOS behind",
                           source={"name": "SOFA (macadmins)", "url": newer[0].get("SecurityInfo") if newer else ""},
                           fix={"type": "open", "item_id": "macos"}))
    return {"findings": out, "data": data, "covered": 1, "data_asof": feeds.asof("sofa")}


ECOS = {"Ruby gems": "RubyGems", "Python packages": "PyPI"}


def check_osv(ctx):
    kev = _kev_set()
    out, covered, notcov, asof, problems = [], 0, 0, [], []
    for source, eco in ECOS.items():
        items = [i for i in ctx["items"] if i["source"] == source]
        st = feeds.fresh_state("osv-" + eco)
        idx = feeds.load_index(eco) if st in ("fresh", "aging") else None
        if idx is None:
            notcov += len(items)
            problems.append("%s database %s" % (eco, "not downloaded yet" if st == "missing" else st))
            continue
        asof.append(feeds.asof("osv-" + eco))
        for it, v in [(i, ver) for i in items for ver in (i.get("all_versions") or [i.get("installed")])]:
            covered += 1
            older = v != it.get("installed")
            recs = idx.get(feeds.norm_name(eco, it["name"]), [])
            unsure = 0
            for r in recs:
                hit = versions.affected(eco, v, r.get("ranges", []), r.get("versions", []))
                if hit is None:
                    unsure += 1
                    continue
                if not hit:
                    continue
                later = [f for f in r.get("fixed", []) if versions.compare(eco, f, v) == 1]
                later.sort(key=functools.cmp_to_key(lambda a, b: versions.compare(eco, a, b) or 0))
                fixed_in = later[0] if later else None
                cves = [a for a in r.get("aliases", []) if a.startswith("CVE-")]
                exploited = bool(kev and any(c in kev for c in cves))
                sev = r.get("severity")
                bundled_copy = (v != it.get("installed")) and v == it.get("default_version")
                fix = {"type": "update", "item_id": it["id"], "fixed_in": fixed_in} if fixed_in else {"type": "none"}
                bundled_copy = older and v == it.get("default_version")
                if bundled_copy:
                    # Ruby's own bundled copy; can't be uninstalled, and the newer copy is what normally loads.
                    fix = {"type": "manual",
                           "note": "This is the copy bundled with Ruby itself. Ruby loads the newer %s you have "
                                   "installed unless a project pins this version. It goes away when Homebrew ships a "
                                   "Ruby with a fixed bundled copy (update Ruby when one is available)."
                                   % it.get("installed")}
                elif older:  # an extra, older copy is installed next to the current one
                    fix = cmd_fix(["gem uninstall %s -v %s" % (shlex.quote(it["name"]), shlex.quote(v))],
                                  note="An older copy is still installed next to %s. Remove it if nothing needs it."
                                  % it.get("installed"))
                if fixed_in and "bundled with Ruby" in (it.get("note") or ""):
                    fix["note"] = "Bundled with Ruby: if gem update can't replace it, update Ruby via Homebrew."
                eff_sev = "low" if bundled_copy and not exploited else (sev or "medium")
                out.append(finding("osv:%s:%s:%s@%s" % (r["id"], source, it["name"], v), "osv", "vuln",
                                   eff_sev, r.get("summary") or r["id"],
                                   ("Affects %s %s%s." % (it["name"], v, " (Ruby's bundled copy; advisory severity: %s)"
                                                          % (sev or "not published") if bundled_copy else "")) +
                                   (" Fixed in %s." % fixed_in if fixed_in else " No fixed version published yet.") +
                                   ("" if sev else " (Severity not published.)"),
                                   item_id=it["id"], subject="%s %s" % (it["name"], v),
                                   refs=[r["id"]] + r.get("aliases", []), exploited=exploited,
                                   label="Exploited" if exploited else ("Bundled copy" if bundled_copy
                                                                        else (sev or "medium").capitalize()),
                                   source={"name": "OSV (local copy)", "url": "https://osv.dev/vulnerability/" + r["id"],
                                           "asof": feeds.asof("osv-" + eco)}, fix=fix))
            if unsure:
                out.append(finding("osv-unsure:%s:%s@%s" % (source, it["name"], v), "osv", "vuln", "info",
                                   "Can't tell whether %d advisories apply to %s %s" % (unsure, it["name"], v),
                                   "The version number couldn't be compared reliably.",
                                   item_id=it["id"], subject=it["name"], label="Can't tell",
                                   source={"name": "OSV (local copy)"}))
    if covered == 0 and problems:
        raise RuntimeError("; ".join(problems))
    res = {"findings": out, "covered": covered, "not_covered": notcov,
           "data_asof": min(asof) if asof else None}
    if problems:
        res["partial"] = "; ".join(problems)
    if kev is None:
        res["partial"] = (res.get("partial", "") + "; " if res.get("partial") else "") + \
            "exploited-list (CISA KEV) unavailable, so 'exploited' can't be shown"
    return res


def check_brew_vulns(ctx):
    if not ctx["settings"].get("net_brew_vulns"):
        raise RuntimeError("switched off — sends your formula list to OSV.dev")
    if not ctx.get("brew"):
        raise RuntimeError("Homebrew not found")
    code, o = _run([ctx["brew"], "vulns", "--json", "--max-summary", "200"], timeout=600)
    try:
        start = min(i for i in (o.find("{"), o.find("[")) if i >= 0)
        data = json.loads(o[start:])
    except ValueError:
        raise RuntimeError("couldn't read brew vulns output (exit %s): %s" % (code, o.strip()[-200:]))
    # Unverified output format: only accept shapes we recognise, otherwise "can't tell" (never a false OK).
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and any(k in data for k in ("findings", "vulnerabilities")):
        rows = data.get("findings", data.get("vulnerabilities"))
    else:
        raise RuntimeError("unrecognised brew vulns JSON (keys: %s) — can't tell"
                           % ", ".join(list(data)[:8]) if isinstance(data, dict) else "unrecognised brew vulns JSON")
    if not isinstance(rows, list):
        raise RuntimeError("unrecognised brew vulns JSON shape — can't tell")
    if code not in (0, 1) and not rows:
        raise RuntimeError("brew vulns exited %s — can't tell" % code)
    kev = _kev_set()
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = r.get("formula") or r.get("name") or r.get("package")
        vid = r.get("id") or r.get("vulnerability") or r.get("osv_id")
        if not name or not vid:
            raise RuntimeError("brew vulns rows have unexpected fields (%s) — can't tell" % ", ".join(list(r)[:8]))
        aliases = r.get("aliases") or []
        sev = str(r.get("severity") or "").lower()
        sev = {"moderate": "medium"}.get(sev, sev) if sev in ("critical", "high", "medium", "moderate", "low") else "medium"
        exploited = bool(kev and any(a in kev for a in aliases + [vid]))
        fixed = r.get("fixed") or r.get("fixed_version") or r.get("fix")
        out.append(finding("brewvuln:%s:%s" % (vid, name), "brew_vulns", "vuln", sev,
                           r.get("summary") or vid, "Affects %s %s." % (name, r.get("version", "")) +
                           (" Fixed in %s." % fixed if fixed else ""),
                           item_id="brew:formula:" + name, subject=name, refs=[vid] + list(aliases),
                           exploited=exploited, label="Exploited" if exploited else sev.capitalize(),
                           source={"name": "brew vulns (OSV.dev)", "url": "https://osv.dev/vulnerability/" + vid},
                           fix={"type": "update", "item_id": "brew:formula:" + name, "fixed_in": fixed}
                           if fixed else {"type": "none"}))
    cov = data.get("coverage") if isinstance(data, dict) else None
    return {"findings": out, "covered": (cov or {}).get("scanned") if isinstance(cov, dict) else None,
            "data": {"raw_keys": list(data)[:10] if isinstance(data, dict) else "list"}}


CHECKS = [
    # id, label, tier, fn
    ("brew_lifecycle", "Homebrew lifecycle (deprecated / disabled)", "fast", check_brew_lifecycle),
    ("posture", "Mac protections", "fast", check_posture),
    ("macos_patch", "macOS patch level", "fast", check_macos_patch),
    ("launch_items", "Background launch items", "fast", check_launch_items),
    ("osv", "Library vulnerabilities (Ruby gems, Python)", "fast", check_osv),
    ("brew_vulns", "Homebrew vulnerabilities (brew vulns)", "deep", check_brew_vulns),
]


# ---------------------------------------------------------------- merge / state
def holds():
    return _read(paths.HOLDS, {})


def is_urgent(f):
    if f.get("state") != "open":
        return False
    if f.get("exploited"):
        return True
    if f["kind"] == "vuln" and f["severity"] == "critical" and f["fix"].get("type") in ("update", "open"):
        return True
    if f["kind"] == "posture" and f["severity"] in ("high", "critical"):
        return True
    if f["kind"] == "persistence" and f.get("new") and f.get("daemon"):
        return True
    return False


def rank(f):
    fixable = f["fix"].get("type") in ("update", "open", "command")
    if f.get("exploited"):
        return 0 if fixable else 1
    s = f["severity"]
    if s in ("critical", "high") and fixable:
        return 2
    if f["kind"] == "posture":
        return 3
    if s in ("critical", "high"):
        return 4
    if s == "medium":
        return 5
    if s == "low":
        return 7
    return 9


def run_checks(ctx, deep=False, log=print):
    prev = _read(paths.SECURITY, {})
    state = _read(paths.SEC_STATE, None)
    baseline_run = state is None
    state = state or {}
    ctx["sec_state"] = state
    prev_checks = prev.get("checks", {})
    prev_by_check = {}
    for f in prev.get("findings", []):
        prev_by_check.setdefault(f["check"], []).append(f)
    first_seen = {f["id"]: f.get("first_seen") for f in prev.get("findings", [])}
    checks, findings = {}, []
    for cid, label, tier, fn in CHECKS:
        if tier == "deep" and not deep:
            if cid in prev_checks:
                checks[cid] = prev_checks[cid]
                findings += prev_by_check.get(cid, [])
            else:
                on = ctx["settings"].get("net_brew_vulns")
                checks[cid] = {"label": label, "tier": tier, "status": "unknown",
                               "error": "runs in the weekly deep check" if on else
                               "switched off — sends your formula list to OSV.dev", "ran": None}
            continue
        t0 = time.time()
        try:
            res = fn(ctx)
            fs = res.get("findings", [])
            status = "issue" if any(f["severity"] != "info" for f in fs) else ("ok" if not res.get("partial") else "partial")
            checks[cid] = {"label": label, "tier": tier, "status": status, "ran": _now(),
                           "seconds": round(time.time() - t0, 2), "error": res.get("partial"),
                           "covered": res.get("covered"), "not_covered": res.get("not_covered"),
                           "data_asof": res.get("data_asof"), "data": res.get("data")}
            findings += fs
        except Exception as e:
            old = prev_checks.get(cid, {})
            checks[cid] = {"label": label, "tier": tier, "status": "unknown", "ran": _now(),
                           "seconds": round(time.time() - t0, 2), "error": str(e)[:300],
                           "data": old.get("data"), "last_ok": old.get("ran") if old.get("status") != "unknown" else old.get("last_ok")}
            for f in prev_by_check.get(cid, []):
                findings.append(dict(f, stale=True))
        log("check %-15s %s%s" % (cid, checks[cid]["status"],
                                   " — " + checks[cid]["error"] if checks[cid].get("error") else ""))
    hl = holds()
    mutes = state.get("mutes", {})
    nowt = time.time()
    for f in findings:
        f["first_seen"] = first_seen.get(f["id"]) or _today()
        f["last_seen"] = _today()
        m = mutes.get(f["id"])
        if m and (m.get("until") is None or m["until"] > nowt):
            f["state"] = "muted"
        elif f.get("item_id") in hl and f["fix"].get("type") == "update":
            f["state"] = "held"
        else:
            f["state"] = "open"
        f["urgent"] = is_urgent(f) or (f["state"] == "held" and (f.get("exploited")))
        f["rank"] = rank(f)
    findings.sort(key=lambda f: (f["rank"], SEV_RANK.get(f["severity"], 9), f["title"]))
    # notifications: new urgent findings, once per id, never on the baseline run
    notified = set(state.get("notified", []))
    new_urgent = [f for f in findings if f["urgent"] and f["id"] not in notified]
    if baseline_run:
        new_urgent_to_notify = []
    else:
        new_urgent_to_notify = new_urgent
    state["notified"] = sorted(notified | {f["id"] for f in new_urgent})
    state.setdefault("since", _today())
    _write(paths.SEC_STATE, state)
    open_f = [f for f in findings if f["state"] == "open"]
    sec = {
        "rev": int(prev.get("rev", 0)) + 1, "updated": _now(), "checks": checks, "findings": findings,
        "summary": {
            "urgent": sum(1 for f in findings if f["urgent"]),
            "review": sum(1 for f in open_f if f["severity"] in ("critical", "high", "medium")),
            "noted": sum(1 for f in open_f if f["severity"] in ("low", "info")),
            "muted": sum(1 for f in findings if f["state"] == "muted"),
            "held": sum(1 for f in findings if f["state"] == "held"),
            "unknown_checks": sum(1 for c in checks.values() if c["status"] == "unknown"),
            "checks": len(checks),
        },
        "coverage": {
            "items": len(ctx["items"]),
            "with_vuln_source": sum(1 for i in ctx["items"] if i["source"] in ECOS) +
            (sum(1 for i in ctx["items"] if i["source"] == "Homebrew formulae")
             if checks.get("brew_vulns", {}).get("status") in ("ok", "issue") else 0),
        },
        "baseline_run": baseline_run,
    }
    _write(paths.SECURITY, sec)
    return sec, new_urgent_to_notify


def ledger():
    st = _read(os.path.join(paths.DATA, "ledger-state.json"), {})
    rows = []
    for lid, e in net.LEDGER.items():
        rows.append(dict(id=lid, label=e[0], host=e[1], sends=e[3], cls=e[4], setting=e[5],
                         **st.get(lid, {})))
    for lid, label, host, sends, cls, setting in net.VIA_TOOL:
        rows.append(dict(id=lid, label=label, host=host, sends=sends, cls=cls, setting=setting))
    return rows


def feeds_status():
    out = {}
    for name in feeds.FEEDS:
        m = feeds.meta(name)
        out[name] = {"state": feeds.fresh_state(name), "asof": feeds.asof(name), "bytes": m.get("bytes"),
                     "error": m.get("error")}
    return out
