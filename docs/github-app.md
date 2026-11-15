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

## Local and durable mode

This local mode scans in the web process, two at a time. It is not an OS sandbox: it strips credentials
from the scanner and stages only the selected files. Before scanning untrusted public repositories, use the
durable mode's isolated worker.

The durable mode (SQLite queue, separate worker, rootless Docker sandbox) is prepared but not live; see
[deploy/README.md](../deploy/README.md).

The App's size limits are in the README's [Scope and limits](../README.md#scope-and-limits).
[ARCHITECTURE.md](../ARCHITECTURE.md) covers the components, trust boundaries and security controls.
