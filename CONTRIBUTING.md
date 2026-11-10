# Contributing to Zeke

Thanks for helping! Zeke is small on purpose: Python standard library only (runs on macOS's `/usr/bin/python3`), one HTML file for the UI, and two tiny Swift programs.

## Ground rules

1. **Spec first.** Behaviour lives in [`docs/SPEC.md`](docs/SPEC.md). Change the spec in the same pull request as the code, including acceptance checks.
2. **Never claim more than we know.** Every status is `current`, `outdated` or `unknown`; every security check is `ok`, `issue` or `unknown`. A failed or stale check must show "can't tell", never "OK".
3. **No new dependencies.** No pip packages, no npm, no frameworks. The engine must keep working after Homebrew upgrades or removes its own Python.
4. **No privileged or destructive actions.** No `sudo`, no deleting, no trusting taps. Show a command to copy instead.
5. **Privacy:** any new network contact needs a row in the privacy ledger (`src/checks/net.py`); anything that sends package or app names to a new party must be opt-in.

## Developing

```sh
git clone https://github.com/Edamuza/zeke && cd zeke
/usr/bin/python3 -m unittest discover -s tests -v     # unit tests (never touch ~/.zeke)
./install.sh                                          # install / upgrade your local copy
zeke scan && zeke open
```

Try the engine against a scratch home without touching your install:

```sh
export ZEKE_HOME=$(mktemp -d) && cp -R src/* "$ZEKE_HOME" && /usr/bin/python3 "$ZEKE_HOME/engine.py" scan
```

Run `app/build.sh` to check the Swift app and helper compile.

## Pull requests

- Keep them focused; include what you tested (and on which macOS / Apple Silicon or Intel).
- New sources (package managers, app updaters) are very welcome. Add a collector in `src/engine.py`, an entry in the spec's sources table, and tests.
- Be kind. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
