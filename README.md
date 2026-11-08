# sast-triage

A GitHub App service that reviews pull requests with Semgrep, **labels each finding new or pre-existing from the pull request's diff, ranks it P1–P3, and fails the check only on new P1 findings**. A pull request is blocked by what it introduced, not by what was already there.

**Status: v1.0, works locally, not deployed.** Its SCA companion, [sca-triage](https://github.com/lansiquo/sca-triage), ranks npm dependency vulnerabilities by whether your code loads them, using the same P1–P3 scale.

## Why

Running Semgrep as a step in a repository's own CI has two problems on pull requests. It reports every finding in the code it scans, including ones the pull request didn't introduce, and the pull request controls its own scan. `sast-triage` runs outside the repository and triages each finding:

| | A Semgrep step in the repo's CI | `sast-triage` |
|---|---|---|
| Scans the pull request's code with Semgrep | ✅ | ✅ changed Python files, at the exact head commit |
| Tells new findings from pre-existing ones | partly: `--baseline-commit` hides pre-existing findings | ✅ labels both, hides neither |
| Ranks by where the code runs | ❌ severity only | ✅ P1–P3: severity × runtime vs test code |
| Fails only on what matters | ❌ `--error` fails on any finding | ✅ only new P1 findings |
| A pull request can't weaken its own scan | ❌ the PR can edit the workflow, ignore files or add `nosemgrep` comments | ✅ service-owned rules; `nosemgrep` is ignored |

## Quick start

Requires Python 3.11–3.13. No GitHub account, token, tunnel, or webhook secret is needed.

```bash
git clone https://github.com/lansiquo/sast-triage.git
cd sast-triage
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make check        # offline tests, then the demo
```

`make test` runs the offline regression suite with outbound HTTP blocked. `make demo` runs real Semgrep on three local fixtures, never executes them, and prints the triage and the resulting GitHub annotation JSON. Scanner or configuration errors exit nonzero.

Make uses `.venv/bin/python` when it exists, otherwise `python3` (override with `PY`). Set `SEMGREP_BIN` to use a specific Semgrep; it fails if that one is unusable.

## What the demo shows (real output)

```text
Pull request (vulnerable.py, test_reports.py): FAILURE
  [P1, new] vulnerable.py:12  py-subprocess-shell-true
  [P1, pre-existing] vulnerable.py:8  py-weak-md5
  [P2, new] test_reports.py:7  py-insecure-deserialization-pickle-loads
  [P2, new] vulnerable.py:16  py-random-for-secrets
  [P3, pre-existing] test_reports.py:11  py-tempfile-mktemp
**Gate: FAIL** — 1 new P1 finding:
- `vulnerable.py:12` py-subprocess-shell-true

clean.py: SUCCESS
**Gate: PASS** — no new P1 findings. Anything else is annotated but doesn't fail the check.
```

The demo simulates one pull request that changes a runtime file and a test file. It produces five findings, and each lands somewhere different on the scale:

| Finding | Why | Result |
|---|---|---|
| `shell=True` | High severity, runtime code, added by this PR | **P1, new**: fails the check |
| MD5 | High severity, runtime code, already there | P1, pre-existing: notice |
| `pickle.loads` | High severity, but in test code | P2, new: warning |
| `random` for a reset token | Medium severity, runtime code | P2, new: warning |
| `tempfile.mktemp` | Medium severity, test code, already there | P3, pre-existing: notice |

Five findings, one blocker. A plain Semgrep step with `--error` would fail this pull request and treat all five the same.

## How findings are triaged

| | Meaning | On the Check Run |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the check when new (red annotation) |
| **P2** | High or critical in test code, or medium in runtime code | Warning when new |
| **P3** | Everything else | Notice |

- **New** means the finding covers at least one line the pull request added or changed, read from GitHub's diff for that file. **Pre-existing** findings are still annotated, as notices, but never fail the check.
- If GitHub sends no diff for a file (it leaves out very large ones) or the diff can't be read, every finding in that file counts as new. A file that was only renamed counts as unchanged, except one moved from test code to runtime code: every finding in it counts as new, since its priority just went up.
- **Test code** follows pytest and Django naming: a `test` or `tests` folder, `test_*.py`, `*_test.py` or `tests.py`. `conftest.py` is ranked as runtime code wherever it is, because pytest imports it on every run, before any test is selected.
- A rule whose metadata rates its own `confidence` or `likelihood` as `LOW` drops one level (P1 to P2, P2 to P3). The bundled rules don't set these yet.

The Check Run title counts the new P1 findings, and the summary shows the gate result and a priority × new/pre-existing table.

## Run it as a GitHub App

1. Configure a GitHub App for **pull request** events with Contents read, Pull requests read, and Checks write permissions.
2. Copy `.env.example` to `.env` and set a strong webhook secret, the App ID and the path to the App's private key. Keep the key outside the repository.
3. Run `make serve`. It loads `.env` by setting `PRSEC_LOAD_DOTENV=1`; the app never reads `.env` otherwise, so `uvicorn app:app` on its own takes configuration from the environment only. `/health` reports liveness. The listener binds to loopback and publishes no API docs or OpenAPI schema.
4. Exposing it through Smee or another tunnel, and installing the App, are separate steps you take yourself. A real webhook **creates real Check Runs**, so use a test repository. This repository never creates grants, installs Apps, changes branch protection or publishes itself.

How it behaves:

- Accepted pull request actions: opened, reopened, synchronize, edited, ready_for_review.
- HMAC-SHA256 signatures are mandatory. `GITHUB_WEBHOOK_SECRETS` takes comma-separated values for rotation.
- Responses: 503 when no secret is configured or the scanner is busy, 401 for a bad signature, 400 for a malformed payload, 413 for a body over 1 MiB, 502 for a GitHub setup failure, and 200 when accepted. Results arrive as Check Runs.
- Only service-owned rules run. Rules and ignore files from the pull request are never used. Whole changed files are scanned at the pull request's head commit.
- Deleted-only or non-Python changes get a neutral result. Scanner errors and partial results fail the check; they never pass it.
- Findings are sorted P1 first, capped at 200 annotations, and uploaded in batches of 50.

A durable deployment mode (SQLite job queue, separate worker, rootless Docker sandbox) is prepared but not deployed. See [deploy/README.md](deploy/README.md).

## Why I built it this way

I wanted a pull request check that answers one question: did this change introduce something serious? Three decisions follow from that.

- **The pull request can't change its own scan.** The rules belong to the service, not the repository, and `nosemgrep` comments are ignored, so a pull request can't edit, skip or suppress the check that reviews it.
- **Labels can over-report, never hide.** If a diff is missing or unreadable, every finding in that file counts as new, and pre-existing findings are still shown, as notices.
- **Fail closed.** Scanner errors, partial results and skipped files fail the check. Only a complete scan can pass.

Next is deploying it behind the rootless Docker sandbox designed in `deploy/`.

## Limits

- **Small Python ruleset.** 15 service-owned rules. It is not a full security audit or proof that code is safe, and pattern matches can need human review. No dependency, secret, JavaScript or infrastructure scanning.
- **Pre-existing means untouched, not unrelated.** A change elsewhere, such as a new import, can make an untouched line match, and that finding is still labelled pre-existing.
- **Size limits fail closed.** Up to a 1 MiB webhook body, a 25 MiB compressed archive, 100 MiB extracted, 10,000 archive members and 3,000 changed files. Larger pull requests fail closed.
- **Local mode is not a deployment.** It runs two concurrent in-memory jobs. The durable mode's guarantees and limits are in the [deployment guide](deploy/README.md).
- **No end-to-end deadline.** Semgrep has a timeout, and HTTP timeouts are per request, not a total deadline.
- **Not an OS sandbox when run locally.** Credentials are removed from the scanner's environment and only the selected files are staged, but use a separate unprivileged worker with CPU, memory and disk limits and no network egress before scanning hostile public repositories.
- **Known dependency findings.** The original local demo environment has them. Use the audited service lock in `deploy/` for deployments.

See [SECURITY.md](SECURITY.md) for the trust boundaries and remaining risks.

## Architecture

```text
GitHub pull request webhook
        |
        v
app.py ---------------------- verify the HMAC signature, validate the payload
        |
        +---> GitHub API ----- changed files and their diffs, head-commit archive
        |
        v
analyzers/semgrep_runner.py - stage the changed .py files, run Semgrep with
        |                     the service-owned rules in trusted_rules.py
        v
analyzers/triage.py --------- new vs pre-existing, P1 / P2 / P3, pass or fail
        |
        v
GitHub Check Run (annotations, summary, conclusion)
```

- `app.py` receives and verifies webhooks, downloads the pull request's head commit, lists the changed files with their diffs, runs the pipeline and completes the Check Run.
- `analyzers/semgrep_runner.py` stages only the changed Python files, runs Semgrep without the service's credentials, rejects incomplete output, and builds the annotations and summary.
- `analyzers/triage.py` reads the diffs, labels each finding new or pre-existing, assigns P1/P2/P3 and decides pass or fail.
- `trusted_rules.py` holds the 15 service-owned Semgrep rules.
- `worker.py`, `job_store.py` and `job_payload.py` are the durable mode: a SQLite job queue and a separate scanning worker. `manage_jobs.py` and `queue_maintenance.py` are operator tools for it.

## Local interactive showcase

Run `.venv/bin/python demo_web.py` and open http://127.0.0.1:8765 to step through ten OWASP Top 10:2025 examples. Four run real Semgrep scans with a small demo ruleset (`demo_rules.py`), and six run behavioral tests on authored fixtures in isolated child processes. The pull request view is simulated, and only bundled fixtures are accepted. Stop it with Ctrl+C. See [the showcase guide](deploy/local-showcase.md).

## Layout

```text
app.py                       webhook service and scan pipeline
analyzers/                   Semgrep runner and triage
trusted_rules.py             the 15 service-owned rules
worker.py, job_store.py      durable mode (SQLite queue, separate worker)
demo.py                      offline demo (make demo)
demo_web.py, demo/           local interactive showcase
tests/                       offline regression suite (make test)
deploy/                      prepared deployment design and evidence (not deployed)
rules/                       early starter rules from 2025, not used by the service
.github/workflows/ci.yml     runs make check on every pull request and push to main
.github/branch-protection/   historical examples, not applied
```

Write-up: [dotrobin.dev/sast-triage](https://dotrobin.dev/sast-triage.html)
