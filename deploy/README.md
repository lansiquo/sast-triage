# Deployment guide (not deployed)

Operator guide for durable mode. No host or credentials are provisioned.

## Integration target

- GitHub App **Security PR Reviewer** (ID `1776205`, owner `lansiquo`), installation `80788483`, which covers all the account's repositories with broad permissions.
- Target repository: `lansiquo/sast-triage`. Its only workflow is CI (`make check`). The webhook points at an HTTPS `smee.io` channel.
- Service-issued tokens are limited to this repository with Contents read, Pull requests read and Checks write. The App's private key is not limited, so moving the PEM to a host needs explicit approval.

## Architecture

- **Host:** a dedicated Linux VM on the mini PC, separate from vulnerable lab VMs; estimated 2 vCPUs, 4 GiB RAM, 20 GiB disk. The queue is single-host SQLite: no ephemeral host, network filesystem or replicated workers.
- **Listener** (`app.py`, web user, behind an HTTPS proxy): verifies the webhook, stores job identifiers in SQLite and acknowledges without calling GitHub. Holds the webhook secret, never the PEM.
- **Worker** (`worker.py`, worker user): recovers interrupted jobs, requests scoped tokens, downloads the exact commit and runs the scanner container. Only it holds the PEM and a dedicated **rootless Docker** daemon. It refuses to start without durable mode, repository/installation scope and the Docker backend.
- **Shared state:** only the SQLite directory, via a queue group (directory 2770, database 660), with `PRSEC_SHARED_STATE=1` and umask `0007` for both services. The web user must not be able to read the PEM or reach the worker's Docker socket. Test this on Linux; local tests do not prove it.
- **Scanner container:** no network, UID/GID 65532, read-only root and mounts, all capabilities dropped, no new privileges, bounded tmpfs, CPU/memory/PID limits, no credentials or Docker socket. The image must be pinned as `name@sha256:...` and runs with `--pull=never`. Repository code is never run.

Details: [trust-boundaries.md](trust-boundaries.md).

## Approval gates

1. **Host:** provision the VM only after approval; no paid provider, tunnel or network expansion is authorized.
2. **Credentials:** approve placing the App key and webhook secret in the host's secret store.
3. **Scanner:** audit an immutable image and run the container tests on rootless Docker. The tested Semgrep 1.182.1 has five unresolved advisories and is not approved ([scanner-security-review.md](scanner-security-review.md); Opengrep alternative in [mini-pc-scanner-evaluation.md](mini-pc-scanner-evaluation.md)).
4. **Cutover:** after the [release checks](#required-release-verification), point the webhook at the approved HTTPS `/webhook` and test a labelled PR without merging it.

Full list: [mini-pc-acceptance.md](mini-pc-acceptance.md).

## Dependencies

- Install the service from `requirements-service.lock` (audited: `pip check` and `pip-audit` clean); `requirements-service.txt` lists direct dependencies. The developer `requirements.txt` has known advisories.
- Semgrep 1.182.1's pins on `mcp` and `opentelemetry-api` block patched versions; do not suppress the findings or bypass the resolver. Semgrep and the service need separate environments (OpenTelemetry conflict).
- The final image needs its own OS/container audit.

## Install and run

Use Python 3.13 and a fresh environment:

```sh
python3.13 -m venv .venv-service
.venv-service/bin/python -m pip install --upgrade pip
.venv-service/bin/python -m pip install -r deploy/requirements-service.lock
.venv-service/bin/python -m pip check
PRSEC_LOAD_DOTENV=0 .venv-service/bin/python -m pytest -q
```

Set [deployment.env.example](deployment.env.example) through the host's secret management, never via unreviewed shell files or arguments, and load the audited image locally. Validate each role as its service user:

```sh
.venv-service/bin/python deploy/check_environment.py --role web
.venv-service/bin/python deploy/check_environment.py --role worker
```

Supervise the two processes separately with restart on failure:

```sh
.venv-service/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
.venv-service/bin/python worker.py
```

Expose only the proxy's HTTPS listener, capped at 1 MiB per request like the app; keep Uvicorn, Docker and SQLite private. Cap logs, monitor queue age and retries, and never erase queue state during updates. Backup (SQLite backup API), restore, migration and the Linux acceptance runner: [production-operations.md](production-operations.md).

## Operations

- **Health:** `/health` is liveness. `/ready` returns 503 unless configuration is complete and the worker heartbeat is under five minutes old; restart a worker stuck past a bounded runtime. It reports queue counts and `degraded: true` when failed jobs need attention. There are no alerts: monitor `/ready`, `job_terminal_failure` logs and the CLI.
- **Retries:** transient failures retry up to eight times, keeping the job and Check ID across restarts; backoff caps at five minutes, but GitHub rate limits can pause the whole queue for longer. Permanent HTTP errors (400, 401, 403, 404, 405, 410, 422) and scanner errors fail the job, and the Check is completed as failure. An exhausted outage, or a failure before or while completing the Check, can leave it in progress until recovered.
- **Recovery:** list failed jobs, fix the cause, then retry (use the configured database path). This resets its attempts, keeps the Check ID, cannot duplicate and makes no GitHub call.

  ```sh
  .venv-service/bin/python manage_jobs.py --db data/jobs.sqlite3
  .venv-service/bin/python manage_jobs.py --db data/jobs.sqlite3 --retry JOB_ID
  ```

- **Deduplication:** by PR and head/base context, across restarts. A reopen gets a fresh job; redelivering it does not. Superseded contexts are cancelled. Base-branch pushes trigger reconciliation if the App subscribes to `push` (subscription not changed). Legacy jobs without base context are quarantined before any API use. Processing is at-least-once: a narrow crash window can duplicate a Check.
- **Limits:** 100 active and 10,000 stored jobs, then 503. Completed jobs are kept 30 days; failed jobs until reviewed. GitHub does not retry failed deliveries, so redeliver missed events after outages.

## Required release verification

Deployment is complete only when these pass on the actual host; none has run.

- Audit the final scanner image; prove non-root, no egress, read-only mounts and bounded resources, output and timeouts.
- Restart the worker mid-scan and between Check creation and persistence; verify recovery against GitHub.
- Check HTTPS `/health` and `/ready`. Prove invalid or unsigned payloads create nothing and a signed payload is queued once across redelivery and restart.
- On a labelled test PR, a vulnerable fixture fails on its exact commit and a clean one then passes; no Check targets another repository or commit. Close it unmerged.

References: [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks), [failed deliveries](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries), [Docker run](https://docs.docker.com/engine/containers/run/).
