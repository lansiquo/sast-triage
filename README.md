# sast-triage

A GitHub App service that reviews pull requests with Semgrep. It labels each finding **new** or **pre-existing** from the pull request's diff, ranks it **P1–P3**, and fails the check only on new P1 findings. A pull request is blocked by what it introduced, not by what was already there.

It runs 15 service-owned rules for high-signal Python patterns. Rules, ignore files and `nosemgrep` comments from the pull request are not used. Findings are review aids, not a security audit. For npm dependencies, see the companion [sca-triage](https://github.com/lansiquo/sca-triage).

**Status: v1.0.** Runs locally and in its own CI; live GitHub deployment is prepared and not yet complete.

## Quick start

Requires Python 3.11–3.14. `requirements.txt` resolves to Semgrep 1.79.0: newer Semgrep pins `opentelemetry-api` below the version current FastAPI needs, and forcing it would also pull in `mcp` and `opentelemetry-api` releases with known advisories. Set `SEMGREP_BIN` to use another Semgrep. The tests and demo need no GitHub account, token or network.

```bash
git clone https://github.com/lansiquo/sast-triage.git
cd sast-triage
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

```bash
make test     # offline regression suite (159 tests), outbound HTTP blocked
make demo     # real Semgrep on local fixtures; prints triage and annotation JSON
make check    # test, then demo
```

To run the webhook service against a GitHub App:

```bash
cp .env.example .env   # set GITHUB_WEBHOOK_SECRET, GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_PATH
make serve             # http://127.0.0.1:8000, liveness at /health
```

The app reads `.env` only when `PRSEC_LOAD_DOTENV=1`, which `make serve` sets. Otherwise it takes configuration from the environment. The App needs **pull request** events with Contents read, Pull requests read and Checks write. A real webhook creates real Check Runs, so use a test repository.

## How triage works

**New or pre-existing.** A finding is new if it covers a line the pull request added or changed. Pre-existing findings are still annotated, as notices.

- No diff for a file (too large or unreadable): every finding in it counts as new.
- Renamed with no changes: unchanged.
- Renamed or copied from test code to runtime code: every finding counts as new, since its priority went up.

**Priority.**

| | Meaning | On the Check Run |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the check when new |
| **P2** | High or critical in test code, or medium in runtime code | Warning when new |
| **P3** | Everything else | Notice |

Test code follows pytest and Django naming: a `test` or `tests` folder, `test_*.py`, `*_test.py` or `tests.py`. `conftest.py` always counts as runtime code. A rule that rates its own confidence or likelihood `LOW` drops one level.

**Gate.** The check fails only when a finding is both new and P1. Scanner errors and partial results also fail it; only a complete scan can pass.

The demo shows this on one simulated pull request: five findings, one blocker.

```text
  [P1, new] vulnerable.py:12  py-subprocess-shell-true
  [P1, pre-existing] vulnerable.py:8  py-weak-md5
  [P2, new] test_reports.py:7  py-insecure-deserialization-pickle-loads
  [P2, new] vulnerable.py:16  py-random-for-secrets
  [P3, pre-existing] test_reports.py:11  py-tempfile-mktemp
**Gate: FAIL** — 1 new P1 finding:
- `vulnerable.py:12` py-subprocess-shell-true
```

## Local interactive showcase

```bash
.venv/bin/python demo_web.py   # http://127.0.0.1:8765
```

Steps through ten OWASP Top 10:2025 examples: four run real Semgrep scans, six run behavioral tests on bundled fixtures. The pull request view is simulated. See [deploy/local-showcase.md](deploy/local-showcase.md).

## Layout

| Path | Contents |
|---|---|
| `app.py` | Webhook service and scan pipeline |
| `analyzers/` | Semgrep runner and triage |
| `trusted_rules.py` | The 15 service-owned rules |
| `rules/` | Extra Semgrep rule packs for manual scans; the service does not load them |
| `worker.py`, `job_store.py` | Durable mode: SQLite queue and separate worker |
| `demo.py` | Offline demo (`make demo`) |
| `demo_web.py`, `demo/` | Local interactive showcase |
| `tests/` | Offline regression suite (`make test`) |
| `deploy/` | Prepared deployment design, runbooks and evidence |
| `.github/workflows/ci.yml` | Runs `make check` on every pull request and push to main |

## Scope and limits

- **Pre-existing means untouched, not unrelated.** A change elsewhere (for example, a new import) can make an untouched line match; that finding stays pre-existing and doesn't fail the check.
- **Size limits fail closed:** 1 MiB webhook body, 25 MiB archive, 100 MiB extracted, 10,000 archive members, 3,000 changed files.
- **Local mode is not an OS sandbox.** It strips credentials from the scanner and stages only the selected files. Before scanning untrusted public repositories, use the durable mode's isolated worker.

## Deployment

The durable mode and rootless Docker sandbox are prepared but not live. See [deploy/README.md](deploy/README.md).

## More

- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup
- Write-up: [dotrobin.dev/sast-triage](https://dotrobin.dev/sast-triage.html)
- [Browser demo](https://dotrobin.dev/demos/sast.html): ten curated OWASP Top 10:2025 examples, triaged in the browser with no setup and no scanning
