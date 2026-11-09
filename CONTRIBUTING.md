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
| `make serve` | The webhook service on `http://127.0.0.1:8000`, reading `.env` |

##### Layout

| Path | Contents |
|---|---|
| `app.py` | Webhook service and scan pipeline |
| `analyzers/` | Semgrep runner and triage |
| `trusted_rules.py` | The 29 service-owned rules |
| `scan_repo.py` | Command-line scan of a whole repository, or of what changed since a git ref (`--base`) |
| `action.yml`, `requirements-cli.txt` | GitHub Action, and the scanner-only install it and the command line use |
| `rules/` | Extra Semgrep rule packs for manual scans; the service does not load them |
| `worker.py`, `job_store.py` | Durable mode: SQLite queue and separate worker |
| `tests/` | Offline regression suite; `tests/fixtures/project` is the `make selfcheck` fixture |
| `deploy/` | Prepared deployment design, runbooks and evidence |
| `docs/branch-protection/` | Branch protection that makes the check required, for a repository that uses the App |
| `.github/workflows/ci.yml` | `make check` on Python 3.11–3.14, and the GitHub Action self-test |
