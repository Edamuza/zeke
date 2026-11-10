# Zeke — Spec (v0.1)

One place to see, check, secure and update every app, tool and library on a Mac.
Runtime and data live in `~/.zeke/` (`ZEKE_HOME`). The dashboard is at **http://127.0.0.1:47800**; the Zeke app wraps it.

## 1. Components

| Path | Role |
|---|---|
| `bin/zeke-apps` | Native helper to see/open/quit apps for Open & update. |
| `engine.py` | The only code that scans or updates. CLI: `scan [--deep]`, `update <id…>`, `update-all`, `plan`, `daily`, `feeds`, `hold`, `mute`, `open`, `open-dashboard`, `status`. |
| `checks/` | Security checks, feed cache, privacy ledger, the only HTTP client (stdlib only). |
| `tests/` | Unit tests (`ZEKE_DATA_DIR` keeps them off real data). |
| `data/security.json`, `security-state.json`, `holds.json`, `feeds/` | Findings; mutes/notified ids/launch-item baseline; holds; cached feeds. |
| `server.py` | Local HTTP server for the dashboard. Calls `engine.py`. |
| `ui/index.html` | Dashboard (single file, no external assets). |
| `daily-gate.sh` | Daily gate (once/day, Wi‑Fi/Ethernet, ≥ 50 Mbps / `ZEKE_MIN_MBPS`, never a phone hotspot) → `engine.py daily`. |
| `config.json` | Written by `install.sh`: your shell `path`, extra `npm_prefixes`, `cli_paths`, `ignore_apps`. |
| `zeke` | CLI wrapper (`zeke open`, `zeke scan`, `zeke plan`, …), linked into `~/.local/bin`. |
| `data/inventory.json` | Last scan result. |
| `data/runs/<run-id>.json` | One record per scan/update run, with per-step exit status. |
| `logs/<run-id>.log` | Full command output for that run. |
| `data/settings.json` | Schedule toggles. |
| `data/token` | Random secret (0600) required on every `/api/*` request; injected by the app, or passed once by `zeke open`. |
| `data/legacy.log` | Optional older log to keep visible in Activity. |

Runtime: `/usr/bin/python3` (macOS system Python, stdlib only) so upgrading/cleaning Homebrew Python can never break the updater.

## 2. Sources (what gets listed)

| Source | Listed from | "Latest" comes from | Update action |
|---|---|---|---|
| Homebrew formulae | `brew info --json=v2 --installed` | same (`versions.stable`) + `brew outdated --greedy --json=v2` | `brew upgrade <name>` |
| Homebrew casks | same | same (greedy, so self-updating casks count) | `brew upgrade --cask <name>` |
| npm globals — **every Node install** found (Homebrew's node, any `node` on your PATH such as nvm/fnm/app-bundled, plus `config.json` `npm_prefixes`), each listed separately | `npm ls -g --json` | `npm outdated -g --json` | `<that npm> install -g -- <pkg>@latest` |
| Ruby gems (Homebrew Ruby only; system Ruby needs sudo) | `gem list --local` | `gem outdated` | `gem update <name>` |
| Python packages (Homebrew python) | `pip3 list --format=json` | `pip3 list --outdated` | `pip3 install -U --break-system-packages <pkg>` — **manual click only**, excluded from Update All (Homebrew owns this Python). `pip` itself is never touched. |
| uv tools | `uv tool list` | `uv tool upgrade --dry-run` not available → status = installed only | `uv tool upgrade <name>` |
| Self-updating CLIs when installed: Claude Code, opencode, uv (official install location first, then PATH, or `config.json` `cli_paths`) | `--version` | npm registry / PyPI (opencode: its own updater) | `claude update`, `opencode upgrade`, `uv self update` |
| App Store apps (`Contents/_MASReceipt`) | Info.plist `CFBundleShortVersionString` | batched Apple lookup by store id, in your Mac's region (from `AppleLocale`), then US | **Open App Store Updates** (no CLI) |
| Other apps in `/Applications` | Info.plist | Homebrew public cask catalog (whole-catalog download, matched by `.app` name) | **Open the app** (its built-in updater). Never reinstalled or adopted via brew. |
| iPhone/iPad apps from the App Store (`Wrapper/iTunesMetadata.plist`) | that plist | Apple lookup by store id | **Open App Store Updates** |
| macOS | `sw_vers` | `softwareupdate -l` | **Open Software Update** (needs restart — never automatic) |

### Known exclusions / edge cases
- **Untrusted taps**: Homebrew refuses to read formulae from taps you haven't trusted, so they're listed as `unknown` with the fix (`brew trust <tap>`) — Zeke never trusts a tap for you.
- **Obsidian-style apps** that update an inner bundle (`obsidian-<v>.asar`) report that version; the installer version is shown separately (`INNER_VERSIONS` in `engine.py`).
- **Safari** and other non-App-Store `com.apple.*` apps update with macOS and are not listed.
- **Apps that come from a Homebrew cask** are listed once, under Homebrew apps (matched by app filename or cask name).
- **App Store listings shared with iPhone** (e.g. Canva, CapCut) and Apple's own iWork apps can't be compared reliably → `unknown`.

## 3. Status rules (three states, never two)

- `current` — installed version equals or is newer than latest.
- `outdated` — a source *explicitly* reports a newer version.
- `unknown` — collector failed, returned nothing, latest is `latest`/unparseable, or no match. **A failed collector never renders as current.** Every collector records `ok` + error text, shown in the UI.

Version compare: numeric dotted compare on the part before `,` (cask build suffix). A shorter *installed* version is padded with zeros (`2.5` < `2.5.1`); a shorter *latest* is compared on the shared prefix (extra build number on the installed side is current). For apps (matched by name or store listing) it is stricter: `current` if the latest version appears inside the installed one (Brave `157.1.99.55` ⊃ `1.99.55`); `unknown` if the first number differs or the installed version is `0.0.0`/unreadable.

## 4. Runs, locking, safety

- Every scan and update takes an exclusive `fcntl` lock on `data/engine.lock`. A second run is **refused** (exit 75, "busy") rather than colliding (two `brew upgrade`s at once deadlock on Homebrew's download locks).
- Commands run as argv lists (no shell), stdin closed, per-step timeout 30 min, `SUDO_ASKPASS` unset. A step that wanted a password is reported as `needs-password`.
- Each step records `{name, argv, exit, seconds, status}`; the run's result is `ok` / `partial` / `failed`.
- After a run, a fresh scan is done and a macOS notification is posted.
- **Update everything is plan-based** (`engine.py plan`): scan first, then candidates = outdated + auto + updatable items, minus holds, pinned formulae and skipped versions. Items with an open vulnerability finding go **first**, per tool, with explicit names (`brew upgrade --formula -- a b`, `gem update -- a b`, `npm install -g -- a@latest`). Python packages, macOS and non-Homebrew apps are never included. The plan is stored in the run record and shown before confirming.
- **Holds** (`data/holds.json`): `hold` (never updated, also refused for single-item Update) or `skip` (only the current latest version; clears when latest moves). A hold always beats a security finding; the finding shows "on hold" instead.
- Package names are checked against `^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$` and passed after `--`.
- **The engine never runs sudo, never deletes, never trusts a tap, never unloads launch items.** Fixes that need these are shown as copyable commands only.
- Runs whose process died show as `interrupted`. Keep the last 200 runs.

## 5. Schedules (all visible in the Schedule tab with loaded state, last run, next run)

| Job | launchd label | When | Does |
|---|---|---|---|
| Dashboard server | `io.github.edamuza.zeke.server` | at login, kept alive | serves the UI |
| Daily auto-update | `io.github.edamuza.zeke.daily` | hourly check + on network change; once/day on fast network | `engine.py daily`: refresh security feeds, then plan-based update-all if `daily_auto` is on |
| Weekly check | `io.github.edamuza.zeke.weekly` | Sunday 10:00 | `engine.py scan --trigger weekly` = scan + **deep** security checks + notification |

Settings (`data/settings.json`): `daily_auto`, `weekly_check`, `notify_security`, `net_brew_vulns` (off). The engine reads them; the gate script only decides *network*. Slow-network back-off: retest after 1 h, then 3 h, then stop for the day. `last-run` is written only after an ok/partial run; a failed run retries once that day.

## 6. Server security

- Binds `127.0.0.1` only.
- Rejects requests whose `Host` isn't `127.0.0.1:47800`/`localhost:47800` (DNS rebinding).
- **The page carries no secret.** Every `/api/*` request (GET and POST) needs `X-Token` = `data/token` (0600). The native app injects the token into its own web view; a browser gets it once via `engine.py open-dashboard` (`/#k=…`, moved to sessionStorage and stripped from the URL). Without it the page shows "Open from the Zeke app". `/api/health` is the only open endpoint.
- POSTs also need a same-origin `Origin` when one is sent. Bodies are type-checked; anything unexpected → 400, never a traceback.
- No endpoint accepts a path, URL or command. Update/open/hold accept only ids from the last scan; mute only ids from `security.json`; settings only known boolean keys; `open-pane` only named System Settings panes.
- Responses send a strict CSP with a per-response script nonce, `nosniff`, `DENY` framing, no referrer. Advisory text is escaped at render time.
- `data/` is 0700; state files 0600.
- API: GET `/api/state`, `/api/security`, `/api/plan`, `/api/runs/<id>/log`, `/api/legacy-log`; POST `/api/scan {deep?}`, `/api/update {ids}`, `/api/update-all`, `/api/open {id}`, `/api/open-pane {key}`, `/api/hold {id, mode, version?, reason?}`, `/api/mute {id, muted, days?}`, `/api/settings`, `/api/feeds`.

## 7. UI

Tabs: **Inventory** (search, filter by status/source/security, sort by risk/status/name, expandable rows with findings + hold controls, per-item Update/Open, Update All with plan preview), **Security** (needs attention, also noted, Mac protections, what was checked + coverage, what leaves this Mac, mute 7/30/90/forever, copyable commands), **Runs & Logs** (run list, per-step status, live log tail, legacy log), **Schedule** (jobs, toggles, Run now). Header: counts by status, last scan time, Scan now. Light/dark. Native app: `/Applications/Zeke.app` (source + `build.sh` in `app/`, installed by `install.sh`). Swift/AppKit window around the dashboard (WKWebView), Dock badge = updates available (`!` prefix when something is urgent), menu bar item (red shield + count when urgent, else update count; security line; Scan Now; Update Everything with plan text; Open at Login), starts the server via `launchctl kickstart` if it's down, refreshes every 60 s (3 s while a run is active). Closing the window keeps it in the menu bar; ⌘Q quits. Rebuild with `~/.zeke/app/build.sh`.

## 8. Acceptance checks

1. Scan counts match direct commands (brew formulae/casks, both npm prefixes, gems, pip, /Applications).
2. Fixture with an outdated item renders as outdated with an Update button.
3. Two concurrent runs → second refused as busy.
4. Cross-origin / token-less POST → 403.
5. Server killed → launchd restarts it.
6. Jobs triggered via `launchctl kickstart` succeed under launchd's environment.
7. Page loads in a browser with no console errors.
8. Scan with security checks stays within ~1 s of the scan without them (today ≈ 6 s total).
9. `compare("2.5","2.5.1")` and `compare_app("4.1","4.1.2,123")` → outdated; `compare_app("157.1.99.55","1.99.55")` → current. (`tests/test_core.py`)
10. Feed missing or older than 14 days → dependent check `unknown`, never `ok`; XProtect shows "can't compare".
11. A KEV-listed CVE on an installed version renders `Exploited`, menu bar shows the red shield, Dock `!`, and exactly one notification across two scans.
13. A deprecated formula with a disable date shows e.g. "Disabled 18 Dec" in Inventory and under Needs attention.
14. Orphaned launch items listed with copyable commands; no `sudo`/`rm`/`bootout` in any run `argv`.
17. A held item is absent from the plan and refused by `/api/update`.
20. `GET /` contains no token; `/api/state` without `X-Token` → 403.
21. `offset=abc` → 400; `Content-Length: -1` → 400; no traceback.
22. Hold/mute with unknown ids → 400.
23. A finding titled `<img src=x onerror=…>` renders as text; CSP header present.
26. Killing the engine mid-run shows `interrupted`; the next scan works.
27. First scan after upgrade notifies nothing (baseline).

Run unit tests from the repo root: `/usr/bin/python3 -m unittest discover -s tests -v` (they use a temp data dir).

## 9. Security checks (`checks/`)

| Check | Tier | Source | Finds |
|---|---|---|---|
| `brew_lifecycle` | every scan | `brew info --json=v2` (already loaded) | deprecated/disabled formulae & casks (medium within 60 days of the disable date, low otherwise, info for dependencies) with the replacement Homebrew suggests; untrusted taps (info) |
| `posture` | every scan | `fdesetup`, `csrutil`, `spctl`, `socketfilterfw`, SoftwareUpdate prefs, `xprotect version` vs SOFA | FileVault/SIP/Gatekeeper off (high), firewall/auto security updates off (medium), XProtect behind (low) |
| `macos_patch` | every scan | SOFA feed + `sw_vers` | macOS behind latest; `exploited` when the newer release fixes actively exploited CVEs |
| `launch_items` | every scan | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` | program missing (medium for root daemons, low for agents); new since baseline (info; urgent if a new root daemon). Report-only |
| `osv` | every scan | local OSV RubyGems + PyPI databases, CISA KEV | known vulnerabilities in **every installed version** of each gem / Python package, "fixed in", exploited flag. Ruby's bundled copies are rated low with the real advisory severity in the text. Unparseable versions → "can't tell" finding |
| `brew_vulns` | weekly deep, **opt-in** | `brew vulns --json` | Homebrew formula vulnerabilities (sends formula list to OSV.dev) |

Finding: `{id, check, kind, severity, title, detail, item_id, subject, refs, source{name,url,asof}, fix{type: update|open|command|manual|none, …}, exploited, state: open|muted|held, urgent, rank, first_seen, last_seen}` in `data/security.json` (separate from inventory; deep-check findings carry over between fast scans). Urgent = open and (exploited, or critical vuln with a fix, or a high posture issue, or a new root daemon). The UI never says "secure"; no badge means "nothing known".

Not covered (shown in the UI): non-Homebrew apps (no reliable vulnerability source), npm globals (would need to send names to OSV.dev — planned as an opt-in toggle).

## 10. Privacy ledger

`checks/net.py` is the only HTTP client; it refuses any URL not in the ledger. Download-only: CISA KEV, SOFA, OSV bulk databases, Homebrew cask catalog, Claude Code / uv latest versions. Sends identifiers: App Store lookup (App Store ids → Apple). Via tools (not enforceable): `brew update`, npm/pip/gem update checks, `softwareupdate`. Opt-in: `brew vulns` (formula list → OSV.dev). Homebrew analytics are disabled for engine-run brew commands (`HOMEBREW_NO_ANALYTICS=1`). The Security tab shows the ledger with last contact and bytes.

## 11. Feeds (`data/feeds/`)

| Feed | URL | Refresh | Can't tell after |
|---|---|---|---|
| CISA KEV | cisa.gov …/known_exploited_vulnerabilities.json | 24 h (scan, 8 s budget) | 14 d |
| SOFA | sofafeed.macadmins.io/v1/macos_data_feed.json | 24 h (scan, 8 s budget) | 14 d |
| OSV RubyGems / PyPI | osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip | 24 h (`engine.py feeds`, daily job) | 14 d |

Conditional GET (ETag / Last-Modified), validated before an atomic swap (KEV ≥ 1000 entries, SOFA has OSVersions, zip passes testzip and size caps); a bad download keeps the old copy. OSV zips are indexed in memory to `osv-<eco>.index.json`. `engine.py feeds` takes its own lock so Scan never reports busy because of a download.

## 12. Open & update (apps that update themselves)

Many apps outside Homebrew only update while they're open and install on quit (Electron/Squirrel, electron-updater, Sparkle). For outdated **Other apps** the Inventory shows **Open & update** (single, or selected together with other items in one run):

1. **Pre-check:** Squirrel/electron-updater/Sparkle apps whose bundle or `~/Library/Caches/<id>.ShipIt` isn't writable by you (e.g. owned by root after a `sudo` install) can never update themselves → step `needs-fix`, app **not opened**, copyable `sudo chown -R <you>:staff …` (never run). Shown in the row as **Fix needed**. Apps with privileged updaters (Chrome, Edge, Brave, Zoom, Adobe) are not flagged. Ownership/mode bits are used, not `os.access()` (App Management makes that say "no" for every app).
2. **Open** in the background via `bin/zeke-apps open` (no focus steal) — unless it's already running, in which case it is watched but **never closed**.
3. **Wait** (polls every 5 s): version on disk changed → done; Squirrel apps: wait until Squirrel stages the update (`ShipItState.plist` / `update.*` newer than the start); others: download activity in the updater's cache (`<id>.ShipIt`, `<updaterCacheDirName>` from `app-update.yml`, Sparkle cache) quiet for 25 s. Limits: 5 min with no activity, 2 min for the Squirrel hand-off after a download, 15 min overall.
4. **Close** with `bin/zeke-apps quit` (NSRunningApplication terminate = normal Quit, may ask to save; no Apple-events permission), wait up to 5 min for the install; if the updater relaunches the app, close it again.
5. **Result** per app: `ok` "updated A → B", or `no-change` with the reason (left open because it was already open / downloaded but waits for the app's own "Restart to update" button / still open, probably showing a dialog / no update offered).

**Stop** (banner button → `POST /api/cancel`, SIGTERM): the running step ends as `cancelled`, apps Zeke opened in this run are closed, the run is marked `cancelled`. Holds work for apps too. Zeke itself and apps in `config.json` `ignore_apps` are excluded (and not listed). App Store apps still go through the App Store.

`bin/zeke-apps` is built by `app/build.sh` from `app/apps-helper.swift`.

Acceptance (verified on the author's Mac): a Squirrel app updated and closed in ~20 s; an already-open app updated and was left open; a root-owned app refused instantly with the fix command; Stop mid-run → `cancelled` and the opened app closed; self / App Store / duplicate ids → 400.
