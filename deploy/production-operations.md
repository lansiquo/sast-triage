# Production operations and acceptance

These are local implementation improvements, not evidence of a live deployment. No GitHub webhook subscription, permissions, credential placement or remote Checks were changed.

## Base-branch changes and durable fanout

Authenticated `push` deliveries are now accepted in durable mode for the configured repository/installation. Tag and deletion events are ignored; invalid refs/SHAs and out-of-scope events are rejected. The listener stores only normalized identifiers and acknowledges without GitHub calls.

The worker enumerates open PRs targeting that branch using the existing pull_requests:read permission, normalizes their current head/base context, and atomically replaces the expansion event with scan jobs. Enumeration does not create a Check. Current context is used if another push overtook the event; normal before/after scan context checks cancel superseded work. Identical PR/head/base jobs deduplicate with ordinary PR deliveries. Repeated expansion after commit creates nothing further. SQLite commits the children and parent completion together; a crash before commit or capacity error leaves no partial fanout. Rate limits use the existing persisted global cooldown and eight-attempt policy.

The portfolio limit is **100 active jobs / at most 100 open PRs per expansion / 10,000 stored jobs**. Over-capacity expansion fails visibly and retries within the existing budget; it never silently drops a subset or reports a scan pass. After fixing capacity or a transient cause, use the existing failed-job recovery tool. More than 100 target PRs requires an intentional capacity/architecture decision. The existing 1-MiB signed webhook limit remains; oversized or undelivered pushes still require operator handling. No polling/reconciliation automation was silently installed.

**Activation gate:** inspect and, only with approval, enable the GitHub App's `push` subscription alongside PR events. Verify a real base-branch update causes fresh exact-context Checks before release. Code support alone does not establish that GitHub is delivering these events. References: [list PRs by base branch](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests), [webhook events](https://docs.github.com/en/webhooks/webhook-events-and-payloads#push).

## Legacy jobs and migration

Schema version 1 records compatibility via SQLite `user_version`; the existing version-0 column layout is preserved. Future versions and incomplete legacy job layouts are refused rather than silently rewritten. Current jobs include base SHA/ref. Legacy active jobs without a valid base SHA are quarantined as `failed: legacy_base_context_missing`, retaining their original job ID and Check ID. Worker startup recovery and per-job execution guard this path before token acquisition. Malformed active JSON payloads are also quarantined on recovery. No base SHA is invented and no old job can receive a false pass from missing context.

Quarantined legacy jobs require a fresh authenticated PR event with complete context. Simply retrying the old payload does not repair it. Existing remote Checks can remain pending until separately authorized recovery/replay; no remote mutation occurs in the migration utility. Completed historical legacy rows remain historical and are not rescanned automatically.

Migration sequence on the approved host, with actual paths substituted:

1. Stop webhook intake and the worker using the approved service supervisor. Keep the existing database and any WAL/SHM files together; never delete them to repair an error.
2. Inspect and create a consistent snapshot. The backup API includes committed WAL data; ordinary copying of only the main file is unsafe.

```sh
.venv-service/bin/python queue_maintenance.py inspect /srv/sast-triage/state/jobs.sqlite3
.venv-service/bin/python queue_maintenance.py backup /srv/sast-triage/state/jobs.sqlite3 /approved-backup-location/before-upgrade.sqlite3
.venv-service/bin/python queue_maintenance.py inspect /approved-backup-location/before-upgrade.sqlite3
```

3. Run the new code's explicit quarantine only with services stopped and the backup verified:

```sh
.venv-service/bin/python manage_jobs.py --db /srv/sast-triage/state/jobs.sqlite3 --quarantine-legacy
.venv-service/bin/python queue_maintenance.py inspect /srv/sast-triage/state/jobs.sqlite3
```

4. Run both role-specific configuration checks below. Review failed jobs, start the worker, and verify `/ready` and local queue state before reopening intake. Arrange replay of missed/legacy events through the approved GitHub process.

## Backup and restore safety

`queue_maintenance.py` imports neither application credentials nor GitHub code. It performs integrity/schema checks, uses SQLite's backup API with a bounded time budget, verifies the result, and atomically publishes a mode-600 snapshot. It refuses existing destination files, symlinks or SQLite sidecars; it never overwrites a live queue. Snapshots preserve job IDs, Check IDs, attempts, states, cooldown and heartbeat metadata.

Restore **to a new path**, then inspect it:

```sh
.venv-service/bin/python queue_maintenance.py restore /approved-backup-location/before-upgrade.sqlite3 /approved-restore-location/restored.sqlite3
.venv-service/bin/python queue_maintenance.py inspect /approved-restore-location/restored.sqlite3
```

An operator must provision the intended shared group/permissions and approve switching the stopped services to the restored path. Snapshot mode 600 is intentionally private; shared deployment uses mode 660 in a mode-2770 directory. Do not point old code at a newer queue: a rollback uses the matching pre-upgrade snapshot and code. Account for events/Checks created since that snapshot; GitHub-to-SQLite recovery is at-least-once and still needs live validation. A restored stale heartbeat is not proof that a worker is running; start the worker and verify current activity.

## Configuration and isolated Linux acceptance

Run `deploy/check_environment.py` as each actual service UID with that role's approved environment (it does not load `.env`):

```sh
.venv-service/bin/python deploy/check_environment.py --role web
.venv-service/bin/python deploy/check_environment.py --role worker
```

Checks cover durable scope, disabled dotenv/token fallback, queue group/mode/schema/integrity and legacy active jobs. Web must receive webhook secrets but no App PEM/Docker connection configuration; worker must receive a protected worker-owned PEM, App ID and digest-pinned Semgrep container, but no webhook secret. Worker preflight also checks the existing rootless daemon and local image. Output names failing requirements without printing configured values. Passing configuration does **not** prove cross-user filesystem denial or an audited image.

On an approved Linux test host, as the non-root worker user, without App credentials, with the final audited image already present:

```sh
export PRSEC_SCANNER_IMAGE='APPROVED_IMAGE@sha256:APPROVED_DIGEST'
# Set the existing approved worker rootless daemon's DOCKER_HOST/context as provisioned.
.venv-service/bin/python deploy/accept_linux.py
```

The runner executes actual container-boundary probes and all 29 production rules. It installs nothing, pulls no image, changes no settings and makes no GitHub calls. It fails immediately on macOS/root or if application credentials are present. Remaining explicit gates: dependency/OS/SBOM audit, separate-UID PEM/socket denial, OOM/PID exhaustion and host reboot recovery, approved HTTPS ingress, and real GitHub delivery/Check/crash-recovery tests. Existing detailed boundary/release runbooks still apply.

## Current evidence

- Tests first reproduced ignored base pushes and legacy jobs reaching credential acquisition.
- Final `make check`: **185 passed**, plus expected real vulnerable/clean scanner fixtures.
- New production tests cover scope/ref validation, deduplication, restart, atomic/concurrent fanout, capacity rollback, rate-limit cooldown, WAL backup/restore, non-overwrite, schema refusal, legacy quarantine/Check identity and safe configuration output.
- GitHub APIs are mocked; SQLite files/concurrency/backup/restore are real local operations.
- `deploy/accept_linux.py` on this Mac exits with **BLOCKED: approved Linux host and non-root worker user required; no tests ran.** Docker's selected daemon remains unreachable. No runtime installation/start or host security changes occurred.
- Official PyPI was checked once: Semgrep 1.182.1 still pins MCP 1.29.0 and OpenTelemetry API ~=1.37.0. Known compatible dependency remediation remains unavailable; no override or waiver applied.

The mini PC is one host option, not a software dependency. The next prerequisite is an approved Linux rootless test environment and an audited compatible scanner image. GitHub push subscription/host secrets/live test PR require their specific approvals at activation time.
