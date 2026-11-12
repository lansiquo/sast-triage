##### Dev setup
1. Use Python 3.11–3.14 (`.python-version` pins 3.12; CI runs all four).
2. Create a virtualenv, install the dependencies and run the checks:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   python -m pip install -r requirements.txt
   make check
   ```
3. Keep `make check` passing. CI runs it on every pull request and push to main, and also runs the
   GitHub Action against the self-check fixture.

| Command | What it runs |
|---|---|
| `make test` | The offline regression suite, with outbound HTTP blocked |
| `make selfcheck` | A full scan of `tests/fixtures/project`; passes when its planted P1 fails the gate |
| `make check` | `make test`, then `make selfcheck` |
| `make package-check` | The package build below, as a test. Needs setuptools 77.0.3 or later; not part of `make check` |
| `make serve` | The webhook service on `http://127.0.0.1:8000`, reading `.env` |

`requirements.txt` pins Semgrep 1.79.0, as `requirements-cli.txt` does: newer Semgrep pins
`opentelemetry-api` below the version current FastAPI needs, and forcing it would also pull in `mcp` and
`opentelemetry-api` releases with known advisories.

##### Package build

`pyproject.toml` describes the command line as the package `sast-triage`. README
"Install as a package (local build)" has the commands; the details behind them:

- setuptools is the only build requirement. The build is offline (`--no-index`) and, with
  `--no-build-isolation`, uses the setuptools that is already installed, which must be 77.0.3 or later:
  it fails without it.
- The install of the wheel is offline too, so it succeeds only where Semgrep 1.79.0 and certifi are
  installed already.
- The version in the wheel's name comes from `pyproject.toml`, where it is written by hand: a release
  sets its final number, such as `2.6.0`, and between releases it is a development version such as
  `2.6.0.dev0`.
- The build leaves `build/` and `sast_triage.egg-info/` in the clone, and git ignores both.
- `make package-check` repeats the build from a development environment that has setuptools 77.0.3 or
  later: it builds the wheel offline from a copy of the checkout in a temporary folder, installs it into
  a fresh virtual environment, and checks that `sast-triage`, run from outside the checkout, scans
  `tests/fixtures/project` with exit status 1 and prints what `python scan_repo.py` prints.

##### Layout

| Path | Contents |
|---|---|
| `app.py` | Webhook service and scan pipeline |
| `analyzers/` | Semgrep runner and triage |
| `trusted_rules.py` | The 41 service-owned rules |
| `scan_repo.py` | Command-line scan of a whole repository, or of what changed since a git ref (`--base`) |
| `action.yml`, `requirements-cli.txt` | GitHub Action, and the scanner-only install it and the command line use |
| `pyproject.toml` | The command line as the package `sast-triage`, for a local build; not published to any index |
| `rules/` | Extra Semgrep rule packs for manual scans; the service does not load them |
| `worker.py`, `job_store.py` | Durable mode: SQLite queue and separate worker |
| `tests/` | Offline regression suite; `tests/fixtures/project` is the `make selfcheck` fixture, and `tests/package_check.py` runs only as `make package-check` |
| `deploy/` | Prepared deployment design, runbooks and evidence |
| `docs/branch-protection/` | Branch protection that makes the check required, for a repository that uses the App |
| `docs/decisions/` | Decision records, one numbered file each: hosting and trust, and the durable-mode scanner |
| `docs/go-live-checklist.md` | The evidence checklist for a durable-mode deployment; every row starts as `NOT_RUN` |
| `.github/workflows/ci.yml` | `make check` on Python 3.11–3.14, and the GitHub Action self-test |
