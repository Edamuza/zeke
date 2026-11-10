# Changelog

## 0.1.0 — first public release

- One inventory for macOS, App Store apps, other apps, Homebrew formulae and casks, npm globals for every Node install, Ruby gems, Python packages, uv tools and self-updating CLIs.
- Three honest states everywhere: up to date, new version, can't tell.
- Security checks: macOS patch level (SOFA), Mac protections (FileVault, SIP, Gatekeeper, firewall, automatic security updates, XProtect), Homebrew deprecations, orphaned/new launch items, known vulnerabilities in every installed gem and Python package (local OSV database + CISA KEV), opt-in `brew vulns`.
- Plan-based "Update everything" with security fixes first, holds and skip-version.
- Open & update for apps that update themselves (Squirrel, electron-updater, Sparkle): opens in the background, waits for the download, quits to install, verifies the version.
- Privacy ledger: one HTTP client that refuses any host not declared; the UI shows what leaves your Mac.
- Native app (Dock badge, menu bar), daily network-gated auto-update, weekly deep check.
