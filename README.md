# Zeke

**Every app, tool and library on your Mac — checked, secured and updated from one place.**

Zeke is a small, local-first update and security center for macOS. It lists everything installed on your Mac — apps, Homebrew, npm, Ruby gems, Python packages, CLIs and macOS itself — tells you honestly what's up to date, what has a new version and what it *can't tell*, checks for known security problems, and updates things on a schedule you control.

No account, no cloud, no telemetry. It runs on the Python that ships with macOS and a tiny native app.

> Status: **0.1.0, early.** Built and tested on Apple Silicon with macOS 27. Feedback and pull requests welcome.

## What it does

**One inventory**

| Source | How Zeke knows the latest version | How it updates |
|---|---|---|
| macOS | `softwareupdate` | opens Software Update (never automatic) |
| App Store apps (incl. iPhone/iPad apps) | Apple's lookup API | opens App Store updates |
| Other apps in `/Applications` | Homebrew's public cask catalog, matched by app name | **Open & update** (below) |
| Homebrew formulae and casks | `brew outdated --greedy` | `brew upgrade` |
| npm globals — for **every** Node install it finds (Homebrew, nvm, fnm, app-bundled…) | `npm outdated -g` | `npm install -g <pkg>@latest` |
| Ruby gems, Python packages (Homebrew's Ruby/Python), uv tools | their own tools | their own tools (pip only when you click) |
| Claude Code, opencode, uv | npm registry / PyPI | their own self-updaters |

Every row is **up to date**, **new version** or **can't tell** — a failed check is never shown as "up to date".

**Security**

- **Known vulnerabilities in every installed version** of your Ruby gems and Python packages, matched *locally* against the OSV database, flagged red when CISA lists the flaw as actively exploited.
- **macOS patch level** (SOFA feed) and **Mac protections**: FileVault, SIP, Gatekeeper, firewall, automatic security updates, XProtect.
- **Homebrew lifecycle:** deprecated and soon-to-be-disabled packages, with the replacement Homebrew suggests.
- **Background launch items** that point to deleted programs, or that appeared since last week.
- **Apps that can't update themselves** (e.g. owned by `root` after a `sudo` install) — with the one-line fix.
- Opt-in `brew vulns` for Homebrew formulae.

Zeke never runs `sudo`, never deletes anything and never trusts a source for you. When a fix needs that, it shows you the exact command to copy.

**Updating**

- **Update everything** shows its plan first: security fixes first, then the rest; items you put **on hold** or whose version you **skipped** are left alone.
- **Open & update** for apps that only update while open (Electron/Squirrel, electron-updater, Sparkle): Zeke opens the app in the background, waits for its updater to download, quits it so the update installs, checks the new version, and closes it. Apps you already have open are never closed.
- **Daily auto-update**, only on Wi-Fi/Ethernet faster than 50 Mbps (never on a phone hotspot), and a **weekly check** with a notification.
- **Activity & logs:** every run records each step, its exit status and full output. You can stop a run.

**Native app:** a window with the dashboard, a Dock badge with the number of updates (`!` when something is urgent), and a menu bar item.

## Privacy

Zeke makes network requests through one client that refuses any host not declared in its **privacy ledger**, and the Security tab shows that ledger with the last contact for each entry.

- **Download only (nothing about you is sent):** CISA's exploited-vulnerability list, the SOFA macOS feed, OSV vulnerability databases, Homebrew's app catalog, latest Claude Code/uv versions.
- **Sends identifiers:** the App Store lookup sends the store IDs of your App Store apps to Apple.
- **Via your package managers:** `brew`, `npm`, `gem`, `pip` and `softwareupdate` contact their own servers as they always do. Homebrew analytics are turned off for commands Zeke runs.
- **Opt-in only:** `brew vulns` sends your Homebrew formula list to OSV.dev (Google).

## Install

Requirements: macOS 14 or newer, Xcode Command Line Tools (`xcode-select --install`). Homebrew is optional but recommended.

```sh
git clone https://github.com/Edamuza/zeke.git
cd zeke
./install.sh
```

This installs the runtime to `~/.zeke`, builds **Zeke.app** into `/Applications`, adds three background jobs (`io.github.edamuza.zeke.server`, `.daily`, `.weekly`), links the `zeke` command into `~/.local/bin`, and runs a first scan. Re-run `./install.sh` after `git pull` to upgrade; your data and settings are kept.

Prefer no app? `./install.sh --no-app` and use `zeke open` to see the dashboard in your browser. (Without the app, the `zeke-apps` helper isn't built either, so **Open & update** isn't available.)

### Using it

- Open **Zeke** from Applications (or the menu bar icon).
- `zeke open` — dashboard in your browser · `zeke scan` · `zeke plan` · `zeke update-all` · `zeke status`

### Configuration

`~/.zeke/config.json` (written by the installer):

```json
{
  "path": "…your shell PATH, so background jobs find the same tools you use…",
  "npm_prefixes": ["~/some/other/node"],
  "cli_paths": {"opencode": "~/.opencode/bin/opencode"},
  "ignore_apps": ["com.example.SomeHelper"]
}
```

Schedules and notifications are switched on and off in the dashboard's **Schedule** tab.

### Uninstall

```sh
./uninstall.sh            # removes the jobs, app and CLI link; keeps ~/.zeke
./uninstall.sh --purge    # also moves ~/.zeke to the Trash
```

## How it works

```
Zeke.app (WKWebView, Dock badge, menu bar) ─┐
browser via `zeke open` ────────────────────┼─▶ server.py  127.0.0.1:47800  (token, Host/Origin checks, CSP)
                                            │        │
launchd: .daily (network-gated), .weekly ───┴──────▶ engine.py ──▶ brew / npm / gem / pip / uv / CLIs / zeke-apps
                                                     │  └─ checks/  security checks, feed cache, privacy-ledgered HTTP
                                                     └─ ~/.zeke/data  inventory, findings, runs, logs (0600)
```

The full behaviour, security model and acceptance checks are in **[docs/SPEC.md](docs/SPEC.md)**.

## Limitations

- macOS only; tested on Apple Silicon. Intel should work but is less tested.
- "Latest version" for apps outside Homebrew and the App Store comes from Homebrew's cask catalog matched by app name; when formats don't line up Zeke says "can't tell" instead of guessing.
- Some apps download an update but wait for you to click their own "Restart to update" button; Zeke tells you when that happens.
- Zeke.app is ad-hoc signed when you build it. There is no notarized download yet.
- npm packages aren't checked for vulnerabilities yet (it would mean sending package names to OSV.dev; planned as an opt-in).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
