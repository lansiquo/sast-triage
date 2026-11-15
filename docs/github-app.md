# Review pull requests with a GitHub App

The webhook service scans each pull request's head commit and reports the result as a Check Run, with up
to 200 annotations, P1 first. It needs the full `requirements.txt`:

```bash
git clone https://github.com/lansiquo/sast-triage.git
cd sast-triage
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # set GITHUB_WEBHOOK_SECRET, GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_PATH
make serve             # http://127.0.0.1:8000, liveness at /health
```

The app reads `.env` only when `PRSEC_LOAD_DOTENV=1`, which `make serve` sets. Otherwise it takes
configuration from the environment.

Register your own GitHub App with **pull request** events and these permissions:

- Contents: read.
- Pull requests: read.
- Checks: write.

A real webhook creates real Check Runs, so use a test repository.

## Severity floor

`PRSEC_SEMGREP_MIN_SEVERITY` sets a severity floor. Findings below it are dropped right after the scan,
before triage. A dropped finding is never reported, gets no priority and can't fail the gate. Leave it
unset unless you mean to hide findings.

The scanner code in `analyzers/semgrep_runner.py` reads it on every scan, so it applies wherever that code
runs:

- The GitHub App and the durable worker. `app.py` sets it to `LOW` when it is unset, which drops nothing.
  The service reads it from its environment, or from `.env` when `PRSEC_LOAD_DOTENV=1`.
- The command line. `scan_repo.py` reads it from its environment and sets no default, so unset means no
  floor.
- The GitHub Action. `action.yml` has no input for it and doesn't set it, but its Scan step runs
  `scan_repo.py` with the workflow's environment, so an `env:` entry for it in your workflow applies.

It applies to the scan of the base version too. Semgrep itself never sees it.

| Value | Effect |
|---|---|
| Unset, empty, `NONE`, `OFF` or `DISABLE` | No floor: every finding is kept |
| `LOW` | Every finding is kept |
| `MEDIUM`, or `WARNING` or `WARN` | Drops low findings |
| `HIGH`, or `ERROR` | Drops medium and low findings |
| `CRITICAL`, or `BLOCKER` | Keeps only critical findings |
| Anything else, such as `INFO` or a misspelling | Counts as `LOW`: every finding is kept, with no error or warning |

Case and surrounding spaces don't matter. A finding at the floor is kept.

The 41 service-owned rules report only high findings (rule severity ERROR, 29 rules) and medium findings
(WARNING, 12 rules). So with those rules:

- `HIGH` hides every medium finding. The gate doesn't change, because only a high or critical finding can
  be P1.
- `CRITICAL` hides every finding, so every complete scan passes the gate. For example,
  `scan_repo.py tests/fixtures/project` then exits with status 0 and reports no findings, not status 1
  for its planted P1.

Scanner errors and malformed scanner output still stop the scan, whatever the floor: exit status 2 from
the command line and the Action, a failed Check Run from the App. They are checked before the floor
applies.

## Local and durable mode

This local mode scans in the web process, two at a time. It is not an OS sandbox: it strips credentials
from the scanner and stages only the selected files. Before scanning untrusted public repositories, use the
durable mode's isolated worker.

The durable mode (SQLite queue, separate worker, rootless Docker sandbox) is prepared but not live; see
[deploy/README.md](../deploy/README.md).

The App's size limits are in the README's [Scope and limits](../README.md#scope-and-limits).
[ARCHITECTURE.md](../ARCHITECTURE.md) covers the components, trust boundaries and security controls.
