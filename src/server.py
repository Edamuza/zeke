#!/usr/bin/python3
"""Zeke dashboard server — http://127.0.0.1:47800 (ZEKE_PORT). Security rules: docs/SPEC.md §6.

- Binds 127.0.0.1 only; Host must be 127.0.0.1:<port> / localhost:<port> (DNS rebinding).
- The page itself carries no secret. Every /api/* request needs X-Token (the native app injects it;
  a browser gets it once via `engine.py open-dashboard`, which opens /#k=<token>).
- POSTs also need a same-origin Origin when one is sent. No endpoint accepts a path, URL or command.
"""
import datetime
import glob
import json
import os
import re
import secrets
import subprocess
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine  # noqa: E402
import checks  # noqa: E402
from checks import paths  # noqa: E402

HOST, PORT = "127.0.0.1", paths.PORT
ALLOWED_HOSTS = {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT}
ALLOWED_ORIGINS = {"http://" + h for h in ALLOWED_HOSTS}
UI = os.path.join(engine.BASE, "ui", "index.html")
TOKEN_FILE = os.path.join(engine.DATA, "token")
LEGACY_LOG = os.path.join(engine.DATA, "legacy.log")  # optional: an older log you want to keep visible
SERVER_LOG = os.path.join(engine.LOGS, "server.log")
UID = os.getuid()
SETTING_KEYS = ("daily_auto", "weekly_check", "net_brew_vulns", "notify_security")
PANES = set(engine.SETTINGS_PANES)

JOBS = [
    (paths.LABEL_PREFIX + ".server", "Dashboard server", "Always on (starts at login, restarted if it stops)"),
    (paths.LABEL_PREFIX + ".daily", "Daily auto-update",
     "Checks hourly + on network change; once a day on Wi‑Fi/Ethernet ≥ 50 Mbps: refresh security data, then update"),
    (paths.LABEL_PREFIX + ".weekly", "Weekly check",
     "Sundays 10:00 — full scan incl. deep security checks, then notifies you"),
]


class Bad(Exception):
    """Client error → 400 with message."""


def token():
    if not os.path.exists(TOKEN_FILE):
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    os.chmod(TOKEN_FILE, 0o600)
    with open(TOKEN_FILE) as f:
        return f.read().strip()


TOKEN = token()


def job_info(label):
    code, out, _ = engine.capture(["launchctl", "print", "gui/%d/%s" % (UID, label)], timeout=10)
    if code != 0:
        return {"loaded": False}
    g = lambda k: (re.search(r"^\s*%s = (.*)$" % re.escape(k), out, re.M) or [None, None])[1]
    return {"loaded": True, "state": g("state"), "last_exit": g("last exit code"), "runs": g("runs"),
            "pid": g("pid")}


def next_weekly():
    now = datetime.datetime.now()
    d = now.replace(hour=10, minute=0, second=0, microsecond=0)
    d += datetime.timedelta(days=(6 - now.weekday()) % 7)
    if d <= now:
        d += datetime.timedelta(days=7)
    return d.astimezone().isoformat(timespec="minutes")


def runs(limit=40):
    cur = engine.current_run()
    out = []
    for p in sorted(glob.glob(os.path.join(engine.RUNS, "*.json")), reverse=True)[:limit]:
        r = engine.read_json(p)
        if not isinstance(r, dict) or "id" not in r:
            continue
        steps = r.get("steps") or []
        r["steps"] = steps
        if r.get("result") == "running" and not (cur and cur.get("id") == r["id"]):
            r["result"] = "interrupted"
        r["steps_ok"] = sum(1 for s in steps if s.get("status") == "ok")
        r["steps_bad"] = [s.get("name") for s in steps if s.get("status") not in ("ok", "running")]
        out.append(r)
    return out


def schedule():
    s = engine.settings()
    try:
        last_run_day = open(os.path.join(engine.DATA, "last-run")).read().strip()
    except OSError:
        last_run_day = None
    jobs = []
    for label, name, when in JOBS:
        j = dict(label=label, name=name, when=when, **job_info(label))
        if label.endswith(".weekly"):
            j["next"] = next_weekly()
        if label.endswith(".daily"):
            j["last_day"] = last_run_day
            j["last_daily"] = engine.read_json(os.path.join(engine.DATA, "last-daily.json"))
        jobs.append(j)
    return {"settings": s, "jobs": jobs}


def security_summary():
    sec = engine.read_json(paths.SECURITY, {}) or {}
    return {"rev": sec.get("rev"), "updated": sec.get("updated"), "summary": sec.get("summary"),
            "checks": {k: v.get("status") for k, v in (sec.get("checks") or {}).items()}}


def spawn(args):
    if engine.current_run():
        return False
    subprocess.Popen(["/usr/bin/python3", os.path.join(engine.BASE, "engine.py")] + args,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True, env=engine.ENV)
    return True


def int_param(q, key, default):
    v = q.get(key)
    if v is None or v == "":
        return default
    if not re.fullmatch(r"-?\d{1,12}", v):
        raise Bad("%s must be an integer" % key)
    return int(v)


class H(BaseHTTPRequestHandler):
    server_version = "UpdateCenter/1.1"
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", nonce=None):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        csp = ("default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; connect-src 'self'; "
               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % nonce) \
            if nonce else "default-src 'none'; frame-ancestors 'none'"
        self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(body)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception:
            # never leak a traceback to the client; keep one line in the log
            with open(SERVER_LOG, "a") as f:
                f.write("%s error: %s\n" % (engine.now_iso(), traceback.format_exc().strip().splitlines()[-1]))
            try:
                self.send(500, {"error": "internal error"})
            except Exception:
                pass

    def host_ok(self):
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def token_ok(self):
        return secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def do_HEAD(self):
        self.send(405, {"error": "use GET"})

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "bad host"})
        path, _, qs = self.path.partition("?")
        q = {}
        for p in qs.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                q[k] = v
        if path == "/":
            nonce = secrets.token_urlsafe(16)
            with open(UI) as f:
                html = f.read().replace("__NONCE__", nonce)
            return self.send(200, html, "text/html", nonce=nonce)
        if path == "/api/health":
            return self.send(200, {"ok": True, "app": "zeke", "version": paths.VERSION})
        if not path.startswith("/api/"):
            return self.send(404, {"error": "not found"})
        if not self.token_ok():
            return self.send(403, {"error": "token required — open from the Zeke app"})
        try:
            if path == "/api/state":
                inv = engine.read_json(engine.INVENTORY, {}) or {}
                return self.send(200, {"inventory": inv, "current": engine.current_run(), "runs": runs(),
                                       "schedule": schedule(), "security": security_summary(),
                                       "legacy_log": os.path.isfile(LEGACY_LOG),
                                       "self_bundles": sorted(engine.SELF_BUNDLES), "app_name": paths.APP_NAME})
            if path == "/api/security":
                sec = engine.read_json(paths.SECURITY, {}) or {}
                return self.send(200, {"security": sec, "ledger": checks.ledger(), "feeds": checks.feeds_status(),
                                       "holds": checks.holds(), "settings": engine.settings()})
            if path == "/api/plan":
                pl = engine.plan()
                pl.pop("_items", None)
                return self.send(200, pl)
            m = re.match(r"^/api/runs/([\w-]{1,80})/log$", path)
            if m:
                return self.tail(os.path.join(engine.LOGS, m.group(1) + ".log"), int_param(q, "offset", 0))
            if path == "/api/legacy-log":
                return self.tail(LEGACY_LOG, int_param(q, "offset", -1))
        except Bad as e:
            return self.send(400, {"error": str(e)})
        return self.send(404, {"error": "not found"})

    def tail(self, p, offset):
        if not os.path.isfile(p):
            return self.send(404, {"error": "no log"})
        size = os.path.getsize(p)
        if offset < 0 or offset > size:
            offset = max(0, size - 200_000)
        with open(p, "rb") as f:
            f.seek(offset)
            data = f.read(1_000_000)
        return self.send(200, {"text": data.decode("utf-8", "replace"), "offset": offset + len(data),
                               "size": size})

    def do_POST(self):
        if not self.host_ok():
            return self.send(403, {"error": "bad host"})
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return self.send(403, {"error": "bad origin"})
        if not self.token_ok():
            return self.send(403, {"error": "bad token"})
        try:
            raw_len = self.headers.get("Content-Length", "0")
            if not re.fullmatch(r"\d{1,6}", raw_len) or int(raw_len) > 100_000:
                raise Bad("bad Content-Length")
            n = int(raw_len)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                raise Bad("bad json")
            if not isinstance(body, dict):
                raise Bad("body must be an object")
            return self.route_post(self.path.split("?")[0], body)
        except Bad as e:
            return self.send(400, {"error": str(e)})

    def route_post(self, path, body):
        busy = {"error": "busy — another scan or update is running"}
        ok = lambda: self.send(202, {"ok": True})
        if path == "/api/scan":
            deep = body.get("deep", False)
            if not isinstance(deep, bool):
                raise Bad("deep must be true/false")
            args = ["scan", "--trigger", "dashboard"] + (["--deep"] if deep else [])
            return ok() if spawn(args) else self.send(409, busy)
        if path == "/api/update-all":
            return ok() if spawn(["update-all", "--trigger", "dashboard"]) else self.send(409, busy)
        if path == "/api/cancel":
            cur = engine.current_run()
            if not cur or not isinstance(cur.get("pid"), int):
                raise Bad("nothing is running")
            try:
                os.kill(cur["pid"], 15)
            except OSError:
                raise Bad("couldn't stop the run")
            return self.send(200, {"ok": True})
        if path == "/api/feeds":
            subprocess.Popen(["/usr/bin/python3", os.path.join(engine.BASE, "engine.py"), "feeds"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, env=engine.ENV)
            return ok()
        inv = engine.read_json(engine.INVENTORY, {}) or {}
        by_id = {i["id"]: i for i in inv.get("items", [])}
        if path == "/api/update":
            ids = body.get("ids")
            if not isinstance(ids, list) or not ids or len(ids) > 400:
                raise Bad("ids required")
            hl = checks.holds()
            if len(set(ids)) != len(ids):
                raise Bad("duplicate ids")
            for i in ids:
                if not isinstance(i, str) or i not in by_id or not (engine.action_for(by_id[i])
                                                                     or engine.app_updatable(by_id[i])):
                    raise Bad("not updatable: %s" % str(i)[:80])
                if (hl.get(i) or {}).get("mode") == "hold" or by_id[i].get("pinned"):
                    raise Bad("%s is on hold — release the hold first" % by_id[i]["name"])
            return ok() if spawn(["update"] + ids + ["--trigger", "dashboard"]) else self.send(409, busy)
        if path == "/api/open":
            i = body.get("id")
            if not isinstance(i, str) or i not in by_id or by_id[i]["action"] != "open":
                raise Bad("not openable")
            return self.send(200, {"ok": engine.cmd_open(i) == 0})
        if path == "/api/open-pane":
            k = body.get("key")
            if not isinstance(k, str) or k not in PANES:
                raise Bad("unknown settings pane")
            return self.send(200, {"ok": engine.open_pane(k) == 0})
        if path == "/api/hold":
            i, mode, ver, reason = body.get("id"), body.get("mode"), body.get("version"), body.get("reason", "")
            if not isinstance(i, str) or i not in by_id or not (by_id[i].get("action") == "update"
                                                                  or engine.app_updatable(by_id[i])):
                raise Bad("not holdable")
            if mode not in ("hold", "skip", "none"):
                raise Bad("mode must be hold, skip or none")
            if mode == "skip" and (not isinstance(ver, str) or ver != by_id[i].get("latest")):
                raise Bad("can only skip the current latest version")
            if not isinstance(reason, str) or len(reason) > 200:
                raise Bad("reason must be text up to 200 characters")
            if engine.cmd_hold(i, mode, ver, reason) != 0:
                raise Bad("couldn't change hold")
            return self.send(200, {"ok": True})
        if path == "/api/mute":
            fid, muted, days = body.get("id"), body.get("muted"), body.get("days")
            sec = engine.read_json(paths.SECURITY, {}) or {}
            if not isinstance(fid, str) or not any(f["id"] == fid for f in sec.get("findings", [])):
                raise Bad("unknown finding")
            if not isinstance(muted, bool) or days not in (None, 7, 30, 90):
                raise Bad("muted must be true/false; days 7, 30, 90 or null")
            engine.cmd_mute(fid, None if (muted and days is None) else (days if muted else "off"))
            return self.send(200, {"ok": True})
        if path == "/api/settings":
            s = engine.settings()
            for k, v in body.items():
                if k not in SETTING_KEYS or not isinstance(v, bool):
                    raise Bad("unknown setting %s" % str(k)[:40])
                s[k] = v
            checks._write(engine.SETTINGS, s)
            return self.send(200, s)
        return self.send(404, {"error": "not found"})


if __name__ == "__main__":
    try:  # keep the server log small
        if os.path.getsize(SERVER_LOG) > 1_000_000:
            open(SERVER_LOG, "w").close()
    except OSError:
        pass
    for p in (paths.SECURITY, paths.SEC_STATE, paths.HOLDS, engine.SETTINGS, engine.INVENTORY):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print("Zeke %s on http://%s:%d" % (paths.VERSION, HOST, PORT), flush=True)
    srv.serve_forever()
