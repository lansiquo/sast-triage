# Deployment guide (not deployed)

Operator guide for durable mode. No host or credentials are provisioned.

## Integration target

- GitHub App **Security PR Reviewer** (ID `1776205`, owner `lansiquo`), installation `80788483`, which today covers all the account's repositories with broad permissions. [Decision 0001](../docs/decisions/0001-hosting-and-trust.md) narrows the installation to the repositories the service scans; that App setting change needs its own approval and has not been made.
- Target repository: `lansiquo/sast-triage`. Its only workflow is CI (`make check`). The webhook points at an HTTPS `smee.io` channel.
- Service-issued tokens are limited to this repository with Contents read, Pull requests read and Checks write. Until the installation is narrowed, the App's private key is not limited, so moving the PEM to a host needs explicit approval.

## Architecture

- **Host:** a dedicated Linux VM on the mini PC, separate from vulnerable lab VMs; estimated 2 vCPUs, 4 GiB RAM, 20 GiB disk. The queue is single-host SQLite: no ephemeral host, network filesystem or replicated workers.
- **Listener** (`app.py`, web user, behind an HTTPS proxy that GitHub reaches only through a tunnel the VM opens outbound; the VM opens no inbound port): verifies the webhook, stores job identifiers in SQLite and acknowledges without calling GitHub. Holds the webhook secret, never the PEM.
- **Worker** (`worker.py`, worker user): recovers interrupted jobs, requests scoped tokens, downloads the exact commit and runs the scanner container. Only it holds the PEM and a dedicated **rootless Docker** daemon. It refuses to start without durable mode, repository/installation scope and the Docker backend.
- **Shared state:** only the SQLite directory, via a queue group (directory 2770, database 660), with `PRSEC_SHARED_STATE=1` and umask `0007` for both services. The web user must not be able to read the PEM or reach the worker's Docker socket. Test this on Linux; local tests do not prove it.
- **Scanner container:** no network, UID/GID 65532, read-only root and mounts, all capabilities dropped, no new privileges, bounded tmpfs, CPU/memory/PID limits, no credentials or Docker socket. The image must be pinned as `name@sha256:...` and runs with `--pull=never`. Repository code is never run.

Details: [trust-boundaries.md](trust-boundaries.md).

## Approval gates

1. **Host:** provision the VM only after approval; no paid provider, tunnel or network expansion is authorized. [Decision 0001](../docs/decisions/0001-hosting-and-trust.md) chooses a tunnel that the VM opens outbound, with no inbound port, as the only way GitHub reaches the webhook; setting it up still needs its own approval.
2. **Credentials:** approve placing the App key and webhook secret in the host's secret store.
3. **Scanner:** audit an immutable image and run the container tests on rootless Docker. [Decision 0002](../docs/decisions/0002-durable-scanner.md) chooses Semgrep 1.79.0, installed with pip from the existing `semgrep==1.79.0` pin into the scanner image, and lists five compatibility results the deployment must show for it, among them `semgrep --version` printing `1.79.0` and all 41 rules passing; no image has been built and none of the five has been shown for a deployment. The tested Semgrep 1.182.1 has five unresolved advisories and is not approved ([scanner-security-review.md](scanner-security-review.md)); Opengrep, evaluated in [mini-pc-scanner-evaluation.md](mini-pc-scanner-evaluation.md), is not chosen.
4. **Cutover:** after the [release checks](#required-release-verification), point the webhook at the approved HTTPS `/webhook` and test a labelled PR without merging it.

Full list: [mini-pc-acceptance.md](mini-pc-acceptance.md).

## Dependencies

- Install the service from `requirements-service.lock` (audited: `pip check` and `pip-audit` clean); `requirements-service.txt` lists direct dependencies. The developer `requirements.txt` and the command line's `requirements-cli.txt` pin `semgrep==1.79.0`; [SECURITY.md](../SECURITY.md) records their pip-audit result.
- The scanner is Semgrep 1.79.0, installed with pip from that pin unchanged into the scanner image, apart from the service environment ([decision 0002](../docs/decisions/0002-durable-scanner.md)). The newest Semgrep tested, 1.182.1, is not used: its pins on `mcp` and `opentelemetry-api` block patched versions. Do not suppress the findings or bypass the resolver.
- The final image needs its own OS/container audit.

## Install and run

Use Python 3.13 and a fresh environment:

```sh
python3.13 -m venv .venv-service
.venv-service/bin/python -m pip install --upgrade pip
.venv-service/bin/python -m pip install -r deploy/requirements-service.lock
.venv-service/bin/python -m pip check
```

The tests need PyYAML and Semgrep, which the service lock leaves out. Run them from a separate environment with the developer `requirements.txt`, which pins Semgrep 1.79.0, as CI does, and never install it into `.venv-service`:

```sh
python3.13 -m venv .venv-test
.venv-test/bin/python -m pip install -r requirements.txt
PRSEC_LOAD_DOTENV=0 .venv-test/bin/python -m pytest -q
```

Set [deployment.env.example](deployment.env.example) through the host's secret management, never via unreviewed shell files or arguments, and load the audited image locally. That image holds Semgrep 1.79.0 from the existing pin (see [Dependencies](#dependencies)); the service lock has no Semgrep. Validate each role as its service user:

```sh
.venv-service/bin/python deploy/check_environment.py --role web
.venv-service/bin/python deploy/check_environment.py --role worker
```

Supervise the two processes separately with restart on failure:

```sh
.venv-service/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
.venv-service/bin/python worker.py
```

Open no inbound port: GitHub reaches only the proxy's HTTPS `/webhook` endpoint, through the tunnel the VM opens outbound ([decision 0001](../docs/decisions/0001-hosting-and-trust.md)), capped at 1 MiB per request like the app; keep Uvicorn, `/health`, `/ready`, Docker and SQLite private. Cap logs, monitor queue age and retries, and never erase queue state during updates. Backup (SQLite backup API), restore, migration and the Linux acceptance runner: [production-operations.md](production-operations.md).

## Operations

- **Health:** `/health` is liveness. `/ready` returns 503 unless configuration is complete and the worker heartbeat is under five minutes old; restart a worker stuck past a bounded runtime. It reports queue counts and `degraded: true` when failed jobs need attention. There are no alerts: monitor `/ready` on the host, `job_terminal_failure` logs and the CLI.
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
- On the host, check `/health` and `/ready` on the loopback listener (`127.0.0.1:8000`); the tunnel reaches only `/webhook`, so they cannot be checked through the public endpoint. Prove invalid or unsigned payloads create nothing and a signed payload is queued once across redelivery and restart.
- On a labelled test PR, a vulnerable fixture fails on its exact commit and a clean one then passes; no Check targets another repository or commit. Close it unmerged.

References: [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks), [failed deliveries](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries), [Docker run](https://docs.docker.com/engine/containers/run/).
