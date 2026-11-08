# Deployment preparation — not deployed

## Verified integration target

- Existing App: **Security PR Reviewer**, ID `1776205`, owned by `lansiquo`.
- Existing installation: `80788483`; it currently covers all the account's repositories with broad permissions.
- Intended service target: **`lansiquo/sast-triage`**, public, default branch `main`.
- Existing webhook destination: HTTPS on `smee.io`. The channel URL is deliberately omitted.
- GitHub reports no deployments and no Actions workflows for this repository.

No App permissions, installation scope, webhook URL, repository settings or secrets have been changed. Service-issued installation tokens are narrowed to this one repository with Contents read, Pull requests read, and Checks write. This does not reduce the parent App credential's authority: moving that PEM to a host requires explicit approval.

## Proposed bounded deployment

The selected future location is a dedicated Linux VM on the mini PC, separated from vulnerable lab VMs. Allocate 2 vCPUs, 4 GiB RAM and 20 GiB persistent disk initially; this is a sizing estimate, not a measured production capacity claim. Use separate unprivileged web/worker users, a preconfigured **rootless Docker** daemon owned only by the worker, and an HTTPS reverse proxy. No hosting purchase is planned. Do not use a sleeping/ephemeral filesystem host, shared network filesystem, or horizontally replicated workers for this SQLite design.

The HTTPS ingress calls FastAPI, which authenticates and validates the webhook, stores only normalized job identifiers in SQLite, and acknowledges without GitHub network calls. A separate single worker takes an exclusive file lock, recovers interrupted jobs, requests narrowly scoped ephemeral tokens, downloads the exact commit, and launches the scanner container. The listener does not need the App private key; only the worker does. Give the listener the webhook secret and both processes the nonsecret scope/queue configuration. Put only the shared SQLite directory in a dedicated queue group (mode 2770), set PRSEC_SHARED_STATE=1, and use umask 0007 for both services. The code requires mode-660 database access in this mode. The web user must not join the worker/Docker group and must not be able to read the worker PEM or its home/runtime socket. Test these permissions on Linux; local tests do not prove a cross-UID boundary.

Scanner containers run without networking, as UID/GID 65532, with a read-only root filesystem, dropped capabilities, no new privileges, a bounded writable tmpfs, CPU/memory/PID limits, read-only source/rules mounts, and no host credentials or Docker socket. The host worker retains access to its rootless Docker socket. It must be dedicated to this service. No repository code, install hook or test command is run.

SQLite provides persistent semantic deduplication by installation/repository/PR/head SHA and recovery after restart. Check Run IDs are persisted. A crash between remote creation and local persistence is reconciled using the exact job's external ID and App ID. This is at-least-once processing, not an exactly-once guarantee across GitHub and SQLite. GitHub eventual consistency can still produce a duplicate in a narrow crash window.

## Approval gates still open

1. **Host:** wait for the mini PC and provision the dedicated Linux VM only after approval. No paid provider, tunnel or network expansion is authorized.
2. **Credentials:** approve placing the existing App private key and webhook secret in the named host's secret store. No upload has occurred.
3. **Scanner:** select and audit an immutable scanner image, then run container integration tests on rootless Docker. The local Docker daemon is unavailable. The current tested Semgrep Python distribution has unresolved dependency advisories; it is not approved for deployment.
4. **Cutover:** once the backend passes the gates, configure the existing App webhook to the approved HTTPS `/webhook` endpoint, verify TLS and signatures, and test a labelled PR in `lansiquo/sast-triage`. This may produce Checks on that test PR; it must not merge it or alter unrelated work.

The existing App's all-repository installation and broad permissions should be reviewed with the owner. Changing them is a separate approval decision, not part of the prepared code changes.

## Dependency evidence (2026-10-29)

- Original environment: 108 known vulnerability findings across 16 packages.
- Isolated updated service/test environment: `pip check` passes and `pip-audit` reports no known vulnerabilities. `requirements-service.lock` records that tested environment; `requirements-service.txt` lists direct runtime dependencies.
- Semgrep `1.182.1` Python environment: five reported vulnerabilities across `mcp==1.29.0` and `opentelemetry-api==1.37.0`. Its exact MCP pin and OpenTelemetry version constraint prevent a straightforward compatible upgrade. MCP fixes listed by the audit are 1.30.0/2.2.0; OpenTelemetry API fix is 1.45.1. Do not suppress these findings or bypass the resolver to claim a clean build.
- Putting Semgrep and current FastAPI in one environment also produces an OpenTelemetry dependency conflict; service and scanner environments are intentionally separate.

This is a point-in-time dependency audit, not a container/OS audit. The final Linux image still needs vulnerability scanning and full tests, including its native Semgrep binary.

## Commands after approvals and provisioning

Use Python 3.13 and a fresh service environment; preserve the existing developer environment:

```sh
python3.13 -m venv .venv-service
.venv-service/bin/python -m pip install --upgrade pip
.venv-service/bin/python -m pip install -r deploy/requirements-service.lock
.venv-service/bin/python -m pip check
PRSEC_LOAD_DOTENV=0 .venv-service/bin/python -m pytest -q
```

Configure the variables in `deployment.env.example` through the approved host's secret management. Do not source unreviewed shell content or put secrets in command-line arguments. Install the audited scanner image locally and set its `name@sha256:...` reference; runtime uses `--pull=never` and refuses mutable tags. Then supervise these as separate processes, with restart-on-failure and restrictive permissions/umask:

```sh
.venv-service/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
.venv-service/bin/python worker.py
```

Expose only the proxy's HTTPS listener. Limit requests to 1 MiB there as well; keep Uvicorn, Docker and SQLite private. Back up the persistent state safely (SQLite backup API), cap logs, and monitor queue age/retries. `/health` is liveness; `/ready` requires a worker heartbeat within five minutes. A long job can make readiness fail conservatively. A supervisor should restart a stuck worker after a bounded maximum runtime so the queue can recover. Do not erase queue state during updates.

Transient remote failures retry for at most eight attempts, preserving the job and Check Run ID across restarts. Ordinary backoff is capped at five minutes; explicit GitHub rate-limit delays can be longer and pause the whole queue persistently. Permanent permission/request failures and scanner infrastructure errors become local `failed` jobs instead of retrying indefinitely. A scan that successfully finds vulnerabilities is a completed job, even though its Check conclusion is failure. Superseded head/base contexts are cancelled.

`/ready` exposes aggregate queue counts and `degraded: true` when failed jobs need attention; it still returns 200 while the worker is alive so historical failures do not stop intake. Safe `job_terminal_failure` logs and the local CLI provide details without payloads or credentials:

```sh
.venv-service/bin/python manage_jobs.py --db data/jobs.sqlite3
# After resolving the reported cause, explicitly retry the indicated job:
.venv-service/bin/python manage_jobs.py --db data/jobs.sqlite3 --retry JOB_ID
```

Use the actual configured database path. Recovery atomically resets the attempt budget and retains the existing Check ID; concurrent repeated recovery requests cannot enqueue duplicates. It does not call GitHub directly. A permanent GitHub error during the scan (HTTP 400, 401, 403, 404, 405, 410 or 422, for example an unreadable commit) completes the Check as failure with the HTTP status in its summary before the job is marked failed. An outage that exhausts the retry budget, or a failure before the Check exists or while completing it, can still leave a GitHub Check in progress until an operator fixes the cause and recovers the job. There are no external notifications: operators must monitor readiness, logs, or CLI status.

Ordinary events deduplicate by normalized head/base context. A legitimate reopen gets a fresh job even at the same head; redelivery of that reopen keeps the same job because GitHub preserves `X-GitHub-Delivery`. A changed base SHA or target branch produces a new job when a subscribed PR webhook arrives. Authenticated base-branch pushes now enqueue bounded durable reconciliation when the App is subscribed to push events; this subscription has not been changed here. Legacy active jobs without base context are quarantined before credentials/API access and require a fresh complete PR event. See [production-operations.md](production-operations.md) for activation, queue bounds and migration.

Completed jobs are retained for 30 days; failed jobs remain for operator review. At most 100 queued/running jobs and 10,000 total stored jobs are accepted. Capacity failures return 503. GitHub does not automatically redeliver failed deliveries, so operators must monitor and redeliver missed events after outages.

## Required release verification

- Build and audit the final immutable Linux scanner image; prove non-root execution, blocked outbound network, read-only mounts, and bounded resource/output/timeout behavior.
- Restart the worker during a scan and between Check creation and persistence; verify recovery and reconciliation against GitHub.
- Check the approved HTTPS `/health` and `/ready` endpoints. Send invalid/unsigned payloads and prove no jobs/Checks are created. Verify a valid signed payload is queued once across redelivery and process restart.
- Create a labelled temporary test PR with a deliberately vulnerable Python fixture, verify failure on its exact commit SHA, replace it with the clean fixture, and verify success on the new SHA. Confirm no check targets an unrelated repo or commit. Close the test PR without merging when finished.
- Deploy is complete only when all of these pass on the actual host. No such deployment or live test has been performed yet.

References: [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks), [GitHub failed deliveries](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries), [Docker runtime controls](https://docs.docker.com/engine/containers/run/).

## Follow-up scanner investigation

See [scanner-security-review.md](scanner-security-review.md) for the supported-version resolver evidence, exact five advisories, source-based reachability assessment, and rootless-container verification plan. No compatible patched official Semgrep release was found; the scanner deployment gate remains closed.

## Mini PC and alternative-scanner preparation

See [mini-pc-scanner-evaluation.md](mini-pc-scanner-evaluation.md) for the tested Opengrep alternative, audit limitations, host prerequisites, and reproducible checks. The default scanner is unchanged. Real container boundary tests are provided in `test_container_boundary.py` and are explicitly unrun on this Mac.

## Production operations update

Read [production-operations.md](production-operations.md) for atomic base-push fanout, legacy quarantine, SQLite schema/backup/restore procedures, role-specific configuration validation and the executable Linux acceptance runner. These local tests do not constitute live deployment approval.
