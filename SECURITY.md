# Security policy

Zeke runs commands that install software on your Mac, so security reports are very welcome.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. You'll get a reply within a week.

Useful details: macOS version, Zeke version (`zeke status` prints it), steps to reproduce, and impact.

## What Zeke promises (and what counts as a bug)

- The dashboard server listens on `127.0.0.1` only and rejects other `Host` headers (DNS rebinding).
- Every `/api/*` request needs the per-install token in `~/.zeke/data/token` (mode 0600). The page itself contains no secret; another local program or website must not be able to start updates, change settings or read your inventory.
- No endpoint accepts a command, path or URL. Updates run only from the engine's own command table, for ids that exist in the last scan, with names validated and passed after `--`.
- Zeke never runs `sudo`, never deletes files, never trusts a Homebrew tap, never unloads launch items. Fixes that need those are shown as text to copy.
- Network access goes through one client that refuses hosts not listed in the privacy ledger (`src/checks/net.py`). Turning on anything that sends your package list to a third party is opt-in.
- Advisory text from feeds is treated as untrusted and escaped; the page sends a strict Content-Security-Policy.

A way to break any of these is a security bug.

## Known limits

- Zeke.app and the `zeke-apps` helper are **ad-hoc signed** when you build them. They're meant to be built from source on your own Mac.
- Commands run by package managers (brew, npm, gem, pip, softwareupdate) make their own network requests; Zeke can't restrict those.
