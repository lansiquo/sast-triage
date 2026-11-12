# Go-live evidence checklist

- Status: no row has run
- Operator: Robin (owner)
- Roadmap item: F-2.3, "Make the go-live evidence checklist reviewable" ([ROADMAP.md](../ROADMAP.md), Step 2)
- Sources: read as they stood on 2026-11-12

This checklist puts in one place every verification that the deployment documents and the two decision records require before the durable-mode GitHub App service counts as deployed. Each row has an expected result and an Evidence field that starts as `NOT_RUN`. Robin is the operator: Robin does the host setup, the live GitHub verification and the monitoring, and fills in the Evidence fields. The checklist adds no requirement of its own, runs nothing and changes no file in `deploy/`.

## Not authorized here

This checklist authorizes no host setup, provisioning, tunnel, credential move, image build or live GitHub change. Each stays a separate owner approval, as [decision 0001](decisions/0001-hosting-and-trust.md) and [decision 0002](decisions/0002-durable-scanner.md) ("Not decided here / not authorized") and [deploy/README.md](../deploy/README.md) ("Approval gates") already say. A row says what to check once the step it depends on is approved. It does not approve the step.

## Sources

| Source | What it adds |
|---|---|
| [deploy/README.md](../deploy/README.md) | "Required release verification", "Approval gates", "Install and run", "Operations" |
| [deploy/mini-pc-acceptance.md](../deploy/mini-pc-acceptance.md) | Six acceptance gates |
| [deploy/production-readiness.md](../deploy/production-readiness.md) | Remaining gates and the next checks to run on the host |
| [deploy/verification-checkpoint.md](../deploy/verification-checkpoint.md) | Pending gates |
| [deploy/production-operations.md](../deploy/production-operations.md) | Activation gate, migration, backup and restore, role checks |
| [deploy/trust-boundaries.md](../deploy/trust-boundaries.md) | Checks between the two service accounts that are still unrun |
| [deploy/backend-checkpoint.md](../deploy/backend-checkpoint.md) | "Prioritized remaining gates" |
| [deploy/scanner-security-review.md](../deploy/scanner-security-review.md) | "Rootless container verification plan (not executed)", steps 1 to 8 |
| [deploy/mini-pc-scanner-evaluation.md](../deploy/mini-pc-scanner-evaluation.md) | Prerequisites list and "Actual rootless boundary test (prepared, not run)" |
| [docs/decisions/0001-hosting-and-trust.md](decisions/0001-hosting-and-trust.md) | The hosting and trust decision (F-2.1) |
| [docs/decisions/0002-durable-scanner.md](decisions/0002-durable-scanner.md) | "Compatibility evidence required before go-live", rows 1 to 5 (F-2.2) |

A check is a row when a source calls it required, a gate, pending or still unrun before deployment, or gives it as a check in its install or migration steps. A check that several documents repeat is one row: the Source column names the place the row's wording comes from, then the other places after "Also". Approvals are not rows.

In the rows, "plan step" means a step of the plan in `deploy/scanner-security-review.md`, "gate" means a numbered gate of the file named, and "prerequisites list" means the list of host prerequisites in `deploy/mini-pc-scanner-evaluation.md`.

## How to fill in a row

- Evidence starts as `NOT_RUN`. `deploy/README.md` ("Required release verification") counts a check only when it passes on the actual host, so a local or CI result does not change a field.
- Replace `NOT_RUN` with the result, the date and where the captured output is kept. `deploy/scanner-security-review.md` (plan step 8) asks to preserve "the image digest, audited package versions, test outputs and cleanup evidence".
- "A missing or failed result is not a pass, and go-live waits for it" (decision 0002).
- "Owner to define" in the Expected result column means the sources state no result. Robin defines one before the row can pass.
- "No command is stated" means the sources say what to observe and give no command for it.
- `QUEUE_DB`, `BACKUP_FILE`, `RESTORE_FILE` and `APPROVED_IMAGE@sha256:APPROVED_DIGEST` are placeholders. This repository is public: host names, addresses, identifiers and secrets stay out of this file.

## Verifications

### 1. Scanner package and image

Kind of work: host setup. Decision 0002 adds: "Each result counts only together with the `semgrep --version` output of the executable that produced it."

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-01 | The pinned scanner package and how it was installed | Record the install command for the scanner image and the file it read (`requirements-cli.txt` or `requirements.txt`, line `semgrep==1.79.0`) | The installed package is `semgrep`, version exactly 1.79.0, from the pin unchanged | Robin | `docs/decisions/0002-durable-scanner.md`, "Compatibility evidence required before go-live", row 1 | NOT_RUN |
| GL-02 | The scanner's version output | `semgrep --version`, run in the scanner image that `PRSEC_SCANNER_IMAGE` names | Standard output is exactly `1.79.0` | Robin | `docs/decisions/0002-durable-scanner.md`, "Compatibility evidence required before go-live", row 2 | NOT_RUN |
| GL-03 | Provenance of the scanner distribution and of the final image | No command is stated for Semgrep 1.79.0. The only signature command in `deploy/` is `deploy/verify_opengrep_signature.py`, for Opengrep, which decision 0002 does not choose | Not stated in `deploy/mini-pc-acceptance.md`, gate 1; owner to define | Robin | `deploy/mini-pc-acceptance.md`, gate 1 ("verify its provenance"). Also: `deploy/verification-checkpoint.md`, last paragraph; `deploy/mini-pc-scanner-evaluation.md`, prerequisites list; `deploy/trust-boundaries.md`, "Signature verification checkpoint" | NOT_RUN |
| GL-04 | Audit of the final scanner image | Audit the complete final Linux image and its SBOM: dependencies and OS packages. No command is stated | Not stated in `deploy/README.md`, "Required release verification"; owner to define. `deploy/mini-pc-acceptance.md`, gate 1, rules out three shortcuts: "Do not override dependencies, suppress advisories, or treat containment as remediation." | Robin | `deploy/README.md`, "Required release verification", bullet 1. Also: the same file, "Approval gates" gate 3 and "Dependencies"; `deploy/mini-pc-acceptance.md`, gate 1; `deploy/verification-checkpoint.md`, last paragraph; `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 2; `deploy/production-operations.md`, "Configuration and isolated Linux acceptance"; `deploy/scanner-security-review.md`, plan prerequisites; `deploy/mini-pc-scanner-evaluation.md`, prerequisites list | NOT_RUN |
| GL-05 | The image digest is recorded and is the audited one | Compare the digest that `PRSEC_SCANNER_IMAGE` names with the digest of the audited image | The two match, and the image is named as `name@sha256:...`, not by a mutable tag | Robin | `deploy/scanner-security-review.md`, plan step 1. Also: plan step 8; `deploy/mini-pc-acceptance.md`, gate 1 ("Record the immutable digest"); `deploy/README.md`, "Architecture"; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks" | NOT_RUN |

### 2. Host and service accounts

Kind of work: host setup.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-06 | The host runs Linux | `uname -s`, as the worker user | Reports Linux; "do not proceed otherwise" | Robin | `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks" | NOT_RUN |
| GL-07 | The worker's Docker daemon is rootless | `docker info --format '{{json .SecurityOptions}}'`, as the worker user | Reports rootless security options; "do not proceed otherwise" | Robin | `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks". Also: the same file, "Verified components and blockers" ("Host containment"); `deploy/scanner-security-review.md`, plan step 1; `deploy/mini-pc-scanner-evaluation.md`, prerequisites list | NOT_RUN |
| GL-08 | Worker startup refuses an unsafe scanner setup | Start the worker with a daemon that is not rootless, with the image missing, and with a mutable tag. No command is stated | The worker rejects each one | Robin | `deploy/scanner-security-review.md`, plan step 1 | NOT_RUN |
| GL-09 | Web role configuration | `.venv-service/bin/python deploy/check_environment.py --role web`, as the web service user with its approved environment | Exit status 0 and `"configuration_ready": true`, the output of `deploy/check_environment.py` when no requirement fails. The web role has webhook secrets and no App private key or Docker connection configuration | Robin | `deploy/mini-pc-acceptance.md`, gate 4. Also: `deploy/README.md`, "Install and run"; `deploy/production-operations.md`, "Configuration and isolated Linux acceptance" and migration step 4 | NOT_RUN |
| GL-10 | Worker role configuration | `.venv-service/bin/python deploy/check_environment.py --role worker`, as the worker service user with its approved environment | Exit status 0 and `"configuration_ready": true`. The worker role has a protected worker-owned App private key, the App ID and a digest-pinned scanner image, and no webhook secret; its preflight finds the rootless daemon and the local image | Robin | `deploy/mini-pc-acceptance.md`, gate 4. Also: `deploy/README.md`, "Install and run"; `deploy/production-operations.md`, "Configuration and isolated Linux acceptance" and migration step 4 | NOT_RUN |
| GL-11 | The web user cannot read the App private key | As the web user, try to read the App private key file. No command is stated | Access is denied: the web identity "must be unable to read the PEM" | Robin | `deploy/mini-pc-acceptance.md`, gate 2. Also: gate 4 ("does not replace cross-UID denial tests"); `deploy/README.md`, "Architecture"; `deploy/trust-boundaries.md`, "Credential ownership" and "Verified tests"; `deploy/production-operations.md`, "Configuration and isolated Linux acceptance"; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-12 | The web user cannot reach the worker's Docker socket | As the web user, try to use the worker's rootless Docker socket. No command is stated | Access is denied | Robin | `deploy/mini-pc-acceptance.md`, gate 2. Also: the places listed for GL-11 | NOT_RUN |
| GL-13 | The shared queue works for both users | Validate SQLite WAL and SHM access to the shared queue by the web user and the worker user, on Linux. No command is stated | Not stated in `deploy/trust-boundaries.md`, "Credential ownership"; owner to define. The setup it names is a mode-2770 directory, a mode-660 database and `PRSEC_SHARED_STATE=1`; `deploy/README.md` adds umask `0007` for both services | Robin | `deploy/trust-boundaries.md`, "Credential ownership". Also: `deploy/mini-pc-scanner-evaluation.md`, prerequisites list and "Actual rootless boundary test (prepared, not run)"; `deploy/README.md`, "Architecture" | NOT_RUN |

### 3. Container boundary and rules

Kind of work: host setup. Run as the worker user, without App credentials, with the audited image already present:

```sh
PRSEC_SCANNER_IMAGE='APPROVED_IMAGE@sha256:APPROVED_DIGEST' \
  .venv-service/bin/python deploy/accept_linux.py
```

`deploy/accept_linux.py` runs `deploy/test_container_boundary.py` (the probe, GL-14 to GL-19) and then `deploy/validate_scanner.py` (GL-20). When both pass it exits with status 0 and prints `"runtime_checks_passed": true`. The probe ends with `PASS: actual rootless container identity, network, capabilities, cgroups, mounts, and credential boundary.` The image must contain `/bin/sh`, `id`, `grep`, `ls` and `touch`: "missing tools are a failed/unrun test, not a pass" (`deploy/mini-pc-scanner-evaluation.md`).

The command is from `deploy/mini-pc-acceptance.md`, gate 3, and `deploy/production-operations.md`, "Configuration and isolated Linux acceptance". The same container tests are required by `deploy/README.md`, "Approval gates", gate 3; `deploy/verification-checkpoint.md`, last paragraph; `deploy/trust-boundaries.md`, "Verified tests"; and `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 2.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-14 | The scanner container is not root | The probe, for the UID. Inspect the running container for the GID; no command is stated | UID and GID 65532 | Robin | `deploy/README.md`, "Required release verification", bullet 1 ("non-root"). Also: the same file, "Architecture"; `deploy/scanner-security-review.md`, plan step 2; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-acceptance.md`, gate 3 | NOT_RUN |
| GL-15 | The scanner container has no network | The probe, for the interface list. An outbound TCP attempt from the container; no command is stated | Network mode `none`: no external routes or interfaces, and no outbound TCP connection succeeds | Robin | `deploy/README.md`, "Required release verification", bullet 1 ("no egress"). Also: `deploy/scanner-security-review.md`, plan steps 2 and 4; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-16 | Capabilities are dropped and privileges cannot grow | The probe | All capabilities dropped and no-new-privileges set | Robin | `deploy/scanner-security-review.md`, plan step 2. Also: `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-acceptance.md`, gate 3; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-17 | The root file system and the mounts are read-only | The probe | Writes to the root file system and to the source and rules mounts fail; a write succeeds only in the bounded tmpfs | Robin | `deploy/README.md`, "Required release verification", bullet 1 ("read-only mounts"). Also: `deploy/scanner-security-review.md`, plan steps 2 and 3; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-18 | The container's resources are bounded | The probe, for the memory and PID limits. Inspect the running container for the CPU limit and the tmpfs bound; no command is stated | One CPU, 768 MiB memory, 128 PIDs and a bounded tmpfs | Robin | `deploy/README.md`, "Required release verification", bullet 1 ("bounded resources"). Also: `deploy/scanner-security-review.md`, plan step 2; `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/mini-pc-scanner-evaluation.md`, prerequisites list | NOT_RUN |
| GL-19 | The container holds no credentials and no host access | The probe | No Docker socket, home directory, App private key or `.env` file is mounted, and no service credential is in the container's environment or mounts | Robin | `deploy/scanner-security-review.md`, plan steps 2 and 3. Also: `deploy/production-readiness.md`, "Minimum prerequisite and executable next checks"; `deploy/trust-boundaries.md`, "Credential ownership"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-20 | The rule sample validation, through the scanner image | `deploy/validate_scanner.py`, run by `deploy/accept_linux.py` through the scanner image | `PASS: all 41 trusted rules; inline nosemgrep cannot suppress MD5 or eval; clean comparison passes.` | Robin | `docs/decisions/0002-durable-scanner.md`, "Compatibility evidence required before go-live", row 4. Also: `deploy/mini-pc-acceptance.md`, gate 3 ("all 41 rule results"); `deploy/production-readiness.md`, "Verified components and blockers" ("Production rules") and "Minimum prerequisite and executable next checks"; `deploy/production-operations.md`, "Configuration and isolated Linux acceptance"; `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 2; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-21 | The container and the host give the same fixture results | Run the vulnerable and clean fixtures in the container and compare normalized rule IDs, exact file and line annotations and conclusions with the host fixture results. No command is stated | Not stated in `deploy/scanner-security-review.md`, plan step 5; owner to define | Robin | `deploy/scanner-security-review.md`, plan step 5 | NOT_RUN |
| GL-22 | An incomplete scan cannot pass | Scan malformed Python and invalid rules in the container. No command is stated | No passing result: "incomplete scans cannot pass" | Robin | `deploy/scanner-security-review.md`, plan step 5 | NOT_RUN |

### 4. Scanner and service checks outside the container

Kind of work: host setup. Decision 0002 notes that GL-23 and GL-24 by default run Semgrep as a host subprocess, not through the scanner image.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-23 | The planted-P1 self-check | `make selfcheck` | `selfcheck: OK, the planted P1 failed the gate (exit 1)` | Robin | `docs/decisions/0002-durable-scanner.md`, "Compatibility evidence required before go-live", row 3 | NOT_RUN |
| GL-24 | The offline suite, with the 41 service-owned rules | `make test`. `deploy/README.md` runs the same suite as `PRSEC_LOAD_DOTENV=0 .venv-service/bin/python -m pytest -q` | The suite passes: 41 rules (21 Python, 20 JavaScript and TypeScript), each matching its positive examples and none of its negative ones | Robin | `docs/decisions/0002-durable-scanner.md`, "Compatibility evidence required before go-live", row 5. Also: `deploy/README.md`, "Install and run" | NOT_RUN |
| GL-25 | The service environment's dependencies are consistent | `.venv-service/bin/python -m pip check` | Clean: `deploy/README.md`, "Dependencies", records the lock as "audited: `pip check` and `pip-audit` clean" | Robin | `deploy/README.md`, "Install and run". Also: the same file, "Dependencies" | NOT_RUN |

### 5. Failures and resource exhaustion

Kind of work: host setup.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-26 | Output overflow fails and cleans up | Make a scan exceed the output bound. No command is stated | A failed result, and the named container is removed | Robin | `deploy/scanner-security-review.md`, plan step 6. Also: `deploy/README.md`, "Required release verification", bullet 1 ("output"); `deploy/mini-pc-acceptance.md`, gate 3 ("timeout/overflow cleanup"); `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-27 | A timeout fails and cleans up | Make a scan exceed its time limit, and make the Docker client time out. No command is stated | A failed result, and the named container is removed, "including when the Docker client times out" | Robin | `deploy/scanner-security-review.md`, plan step 6. Also: `deploy/README.md`, "Required release verification", bullet 1 ("timeouts"); `deploy/mini-pc-acceptance.md`, gate 3 ("timeout/overflow cleanup"); `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-28 | Reaching the memory limit cannot pass | Exhaust the container's memory limit. No command is stated | No successful check | Robin | `deploy/scanner-security-review.md`, plan step 6. Also: `deploy/mini-pc-acceptance.md`, gate 3 ("OOM/PID exhaustion"); `deploy/production-operations.md`, "Configuration and isolated Linux acceptance"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-29 | Reaching the PID limit cannot pass | Exhaust the container's PID limit. No command is stated | No successful check | Robin | `deploy/scanner-security-review.md`, plan step 6. Also: `deploy/mini-pc-acceptance.md`, gate 3 ("OOM/PID exhaustion"); `deploy/production-operations.md`, "Configuration and isolated Linux acceptance" | NOT_RUN |
| GL-30 | A failed cleanup cannot pass | Deny the container cleanup, and lose the Docker daemon during a scan. No command is stated | "a failed absence check must never produce a pass" | Robin | `deploy/mini-pc-acceptance.md`, gate 3. Also: `deploy/backend-checkpoint.md`, "Fail-closed follow-up" | NOT_RUN |
| GL-31 | Host reboot | Reboot the host. No command is stated | Not stated in `deploy/mini-pc-acceptance.md`, gate 3; owner to define. `deploy/production-operations.md` calls the gate "host reboot recovery" | Robin | `deploy/mini-pc-acceptance.md`, gate 3. Also: `deploy/production-operations.md`, "Configuration and isolated Linux acceptance" | NOT_RUN |
| GL-32 | Malicious archive test | An "actual malicious archive" test. No command is stated | Not stated in `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)"; owner to define | Robin | `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-33 | Resource measurements on the host | Take real Linux resource measurements on the host. No command is stated | Not stated in `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)"; owner to define. The same file, "Concrete code improvements", says the 768 MiB memory limit "remains a release-test gate" | Robin | `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)". Also: the same file, prerequisites list and "Concrete code improvements" | NOT_RUN |

### 6. Queue backup, restore and migration

Kind of work: host setup. Run with webhook intake and the worker stopped.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-34 | A consistent backup of the queue | `.venv-service/bin/python queue_maintenance.py inspect QUEUE_DB`, then `queue_maintenance.py backup QUEUE_DB BACKUP_FILE`, then `queue_maintenance.py inspect BACKUP_FILE` | A verified mode-600 snapshot that includes committed WAL data and preserves job IDs, Check IDs, attempts, states, cooldown and heartbeat metadata | Robin | `deploy/mini-pc-acceptance.md`, gate 4 ("verify a WAL-consistent backup"). Also: `deploy/production-operations.md`, "Legacy jobs and migration", steps 1 and 2, and "Backup and restore safety" | NOT_RUN |
| GL-35 | A restore into a new location | `.venv-service/bin/python queue_maintenance.py restore BACKUP_FILE RESTORE_FILE`, then `queue_maintenance.py inspect RESTORE_FILE` | The snapshot is restored to a new path, never over a live queue, with Check IDs and cooldowns preserved | Robin | `deploy/mini-pc-acceptance.md`, gate 4 ("inspect/restore into a new location"). Also: `deploy/production-operations.md`, "Backup and restore safety" | NOT_RUN |
| GL-36 | Legacy jobs are quarantined | With the backup verified: `.venv-service/bin/python manage_jobs.py --db QUEUE_DB --quarantine-legacy`, then `queue_maintenance.py inspect QUEUE_DB`. Then arrange replay of missed and legacy events "through the approved GitHub process" | Active legacy jobs without a valid base SHA are `failed: legacy_base_context_missing` and keep their job ID and Check ID | Robin | `deploy/mini-pc-acceptance.md`, gate 4 ("quarantine/replay legacy contextless jobs"). Also: `deploy/production-operations.md`, "Legacy jobs and migration", steps 3 and 4 | NOT_RUN |
| GL-37 | The service is ready before intake reopens | Review failed jobs, start the worker, then check `/ready` and the local queue state | Not stated in `deploy/production-operations.md`, "Legacy jobs and migration", step 4; owner to define. What `/ready` returns is under GL-39 | Robin | `deploy/production-operations.md`, "Legacy jobs and migration", step 4. Also: the same file, "Backup and restore safety" ("start the worker and verify current activity") | NOT_RUN |

### 7. Ingress and the GitHub App

Kind of work: live GitHub verification.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-38 | The App installation's scope and permissions | Confirm the installation's repository scope and permissions on GitHub. No command is stated | The installation covers the target repository with Contents read, Pull requests read and Checks write, the permissions that `deploy/production-readiness.md` says the service's tokens request. Decision 0001 narrows the scope: see its "Existing statements that differ", point 1 | Robin | `deploy/mini-pc-acceptance.md`, gate 5. Also: `deploy/production-readiness.md`, "Verified components and blockers" and "Minimum prerequisite and executable next checks"; `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 3 | NOT_RUN |
| GL-39 | `/health` and `/ready` over HTTPS | Request `/health` and `/ready` over HTTPS. No command is stated | Not stated in `deploy/README.md`, "Required release verification"; owner to define. The same file, "Operations", says `/health` is liveness and `/ready` returns 503 unless configuration is complete and the worker heartbeat is under five minutes old. Decision 0001, "Existing statements that differ", point 2, says the two cannot be checked through the public endpoint | Robin | `deploy/README.md`, "Required release verification", bullet 3 | NOT_RUN |
| GL-40 | Invalid or unsigned payloads create nothing | Send the webhook an unsigned payload and one with an invalid signature. No command is stated | Nothing is queued | Robin | `deploy/README.md`, "Required release verification", bullet 3. Also: `deploy/mini-pc-acceptance.md`, gate 5 ("verify invalid signatures cannot queue work") | NOT_RUN |
| GL-41 | A signed payload is queued once | Deliver a signed payload, redeliver it and restart. No command is stated | Queued once across redelivery and restart | Robin | `deploy/README.md`, "Required release verification", bullet 3. Also: the same file, "Operations" ("Deduplication"); `deploy/mini-pc-acceptance.md`, gate 6 ("duplicate deliveries") | NOT_RUN |
| GL-42 | Pull request lifecycle events are delivered | Observe real deliveries of normal pull request lifecycle events. No command is stated | The events are delivered: "code support is not subscription evidence" | Robin | `deploy/mini-pc-acceptance.md`, gate 5. Also: `deploy/production-readiness.md`, "Verified components and blockers"; `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 3; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-43 | A base-branch update scans open pull requests again | With the App's `push` subscription enabled, which needs its own approval, update the base branch of an open test pull request. No command is stated | "a real base-branch update causes fresh exact-context Checks" | Robin | `deploy/production-operations.md`, "Base-branch changes and durable fanout" ("Activation gate"). Also: `deploy/mini-pc-acceptance.md`, gate 5 and gate 6 ("base updates") | NOT_RUN |

### 8. Live acceptance on a test pull request

Kind of work: live GitHub verification, on an approved, labelled, temporary test pull request in the target repository.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| GL-44 | A vulnerable fixture fails | Push a vulnerable fixture to the test pull request | The Check fails on that exact commit | Robin | `deploy/README.md`, "Required release verification", bullet 4. Also: the same file, "Approval gates", gate 4; `deploy/mini-pc-acceptance.md`, gate 6; `deploy/production-readiness.md`, "Verified components and blockers"; `deploy/backend-checkpoint.md`, "Prioritized remaining gates", item 3 | NOT_RUN |
| GL-45 | A clean fixture then passes | Push the clean version to the same pull request | The Check passes on that exact commit | Robin | `deploy/README.md`, "Required release verification", bullet 4. Also: `deploy/mini-pc-acceptance.md`, gate 6 | NOT_RUN |
| GL-46 | No Check targets another repository or commit | Review every Check the test created | None targets another repository or commit | Robin | `deploy/README.md`, "Required release verification", bullet 4. Also: `deploy/scanner-security-review.md`, plan step 7 | NOT_RUN |
| GL-47 | The test pull request is closed unmerged | Close the test pull request | Closed, not merged, and no unrelated work altered | Robin | `deploy/README.md`, "Required release verification", bullet 4. Also: the same file, "Approval gates", gate 4; `deploy/mini-pc-acceptance.md`, gate 6 | NOT_RUN |
| GL-48 | The worker recovers from a restart during a scan | Restart the worker while it scans. No command is stated | "the durable job is recovered, the exact external ID/App ID is reconciled, and only the intended repository/commit is targeted" | Robin | `deploy/README.md`, "Required release verification", bullet 2. Also: `deploy/scanner-security-review.md`, plan step 7; `deploy/mini-pc-acceptance.md`, gate 6; `deploy/production-readiness.md`, "Verified components and blockers"; `deploy/mini-pc-scanner-evaluation.md`, "Actual rootless boundary test (prepared, not run)" | NOT_RUN |
| GL-49 | The worker recovers from a restart between Check creation and persistence | Restart the worker after the Check is created and before its ID is saved. No command is stated | The result quoted for GL-48, verified against GitHub. `deploy/README.md`, "Operations", adds that processing is at-least-once: "a narrow crash window can duplicate a Check" | Robin | `deploy/README.md`, "Required release verification", bullet 2. Also: `deploy/scanner-security-review.md`, plan step 7 | NOT_RUN |
| GL-50 | A stale scan is cancelled | Close the test pull request or change its head while a scan runs, as `deploy/backend-checkpoint.md`, "Concrete fixes", describes. No command is stated | The result is cancelled, not published as current | Robin | `deploy/mini-pc-acceptance.md`, gate 6 ("stale cancellation"). Also: `deploy/backend-checkpoint.md`, "Concrete fixes"; `deploy/README.md`, "Operations" ("Deduplication") | NOT_RUN |
| GL-51 | Transient token and API failures are retried | Observe a transient token or API failure. The sources do not say how to cause one | The job is retried and keeps its job and Check ID across restarts. It gets eight attempts in total, then it is marked failed: `job_store.py` (`MAX_ATTEMPTS = 8`) and `ARCHITECTURE.md`, "Failure handling" ("after 8 attempts it is marked failed"). `deploy/README.md`, "Operations", says "retry up to eight times" instead: see point 10 under "Where the sources disagree" | Robin | `deploy/mini-pc-acceptance.md`, gate 6 ("transient token/API failures"). Also: `deploy/README.md`, "Operations" ("Retries") | NOT_RUN |
| GL-52 | A rate limit pauses the queue | Observe a GitHub rate limit. The sources do not say how to cause one | A persistent cooldown blocks every claim until the limit's time, "including after restart" | Robin | `deploy/mini-pc-acceptance.md`, gate 6 ("cooldown"). Also: `deploy/backend-checkpoint.md`, "Concrete fixes"; `deploy/README.md`, "Operations" ("Retries") | NOT_RUN |
| GL-53 | A permanent failure is visible | Observe a permanent failure. The sources do not say how to cause one | The job fails, the Check is completed as failure, and `/ready` reports `degraded: true` | Robin | `deploy/mini-pc-acceptance.md`, gate 6 ("permanent-failure visibility"). Also: `deploy/README.md`, "Operations" ("Health" and "Retries") | NOT_RUN |
| GL-54 | The remaining recovery limits are recorded | Record the remaining at-least-once recovery limits | Not stated in `deploy/mini-pc-acceptance.md`, gate 6; owner to define | Robin | `deploy/mini-pc-acceptance.md`, gate 6 | NOT_RUN |

## Monitoring

Kind of work: monitoring, after go-live. `deploy/README.md`, "Operations", says "There are no alerts", so each row is something the operator looks at. No source says how often.

| ID | Verification | Command or observation | Expected result | Run by | Source | Evidence |
|---|---|---|---|---|---|---|
| MON-1 | Readiness | Request `/ready` | `/ready` returns 503 unless configuration is complete and the worker heartbeat is under five minutes old. It reports queue counts, and `degraded: true` when failed jobs need attention. Restart a worker stuck past a bounded runtime | Robin | `deploy/README.md`, "Operations" ("Health") | NOT_RUN |
| MON-2 | Terminal job failures | Watch the service logs for `job_terminal_failure` | Each line identifies a failed job and its reason | Robin | `deploy/README.md`, "Operations" ("Health"). Also: `deploy/backend-checkpoint.md`, "Lifecycle and failure-recovery follow-up" | NOT_RUN |
| MON-3 | Failed jobs | `.venv-service/bin/python manage_jobs.py --db QUEUE_DB` lists them. After fixing the cause, add `--retry JOB_ID` | Failed jobs are listed and are kept until reviewed. A retry resets the job's attempts, keeps its Check ID, cannot duplicate and makes no GitHub call | Robin | `deploy/README.md`, "Operations" ("Health", "Recovery" and "Limits") | NOT_RUN |
| MON-4 | Queue age and retries | Monitor queue age and retries. No command is stated | Not stated in `deploy/README.md`, "Install and run"; owner to define. The limits the same file states are 100 active and 10,000 stored jobs, then 503 | Robin | `deploy/README.md`, "Install and run". Also: `deploy/mini-pc-scanner-evaluation.md`, prerequisites list | NOT_RUN |
| MON-5 | Unconfirmed container cleanup | Watch the logs for `container_cleanup_unconfirmed` | When it appears: inspect the exact generated container name and resolve the orphan or daemon issue before resuming workload | Robin | `deploy/mini-pc-acceptance.md`, gate 3. Also: `deploy/backend-checkpoint.md`, "Fail-closed follow-up" | NOT_RUN |
| MON-6 | Missed deliveries after an outage | After an outage, redeliver the missed events | Missed events are redelivered by the operator: "GitHub does not retry failed deliveries". Oversized or undelivered pushes also need operator handling | Robin | `deploy/README.md`, "Operations" ("Limits"). Also: `deploy/production-operations.md`, "Base-branch changes and durable fanout" | NOT_RUN |

## Where the sources disagree

No file in `deploy/` is changed here. Each point is a follow-up item for later work.

### Already listed in the decision records

These are not repeated here. They affect the rows named.

- Decision 0001, "Existing statements that differ", point 1 (installation scope): GL-38.
- Decision 0001, point 2 (how the webhook endpoint is reached): GL-39 to GL-43.
- Decision 0002, "Existing statements that differ", point 1 (the documents gate on Semgrep 1.182.1): GL-03 and GL-04. The gate to resolve that version's five advisories, or to obtain a newer supported distribution, is not a row, because the decision selects 1.79.0.
- Decision 0002, point 2 (Opengrep): the Opengrep release signature check is not a row, because under the decision it "is not a go-live step".
- Decision 0002, point 3 (recorded results cover 15 rules): GL-20 uses 41.
- Decision 0002, point 4 (how the scanner is installed): GL-01, GL-24 and GL-25.

### Found while gathering the rows

1. **Two lists of what must pass.** `deploy/README.md`, "Required release verification", has four bullets and says "Deployment is complete only when these pass". `deploy/mini-pc-acceptance.md` has six gates and says "Until these gates pass" the system is locally tested code. The second list holds checks the first does not: GL-03, GL-05, GL-09 to GL-12, GL-16, GL-20, GL-28 to GL-31, GL-34 to GL-36, GL-38, GL-42, GL-43 and GL-50 to GL-54. This checklist holds both lists.
2. **When credentials are placed.** `deploy/README.md`, "Approval gates", puts the credentials gate (2) before the scanner gate (3), and `deploy/mini-pc-acceptance.md` sets up the worker-owned App private key in gate 2, before the container checks of gate 3. `deploy/verification-checkpoint.md`, last paragraph, runs the container test and the audit first, "then obtain approval for credential placement and network exposure".
3. **Which host to wait for.** `deploy/mini-pc-scanner-evaluation.md`, "Current decision", says to wait for particular hardware. `deploy/mini-pc-acceptance.md` (first paragraph), `deploy/production-readiness.md` (first paragraph) and `deploy/production-operations.md` (last paragraph) say an approved Linux VM is enough. Decision 0001 names one dedicated Linux VM and no hardware.
4. **Two ways to run the container checks.** `deploy/mini-pc-acceptance.md`, gate 3, and `deploy/production-operations.md` run `deploy/accept_linux.py`. `deploy/production-readiness.md` and `deploy/mini-pc-scanner-evaluation.md` run `deploy/test_container_boundary.py` and `deploy/validate_scanner.py` directly, each with a different set of exported variables. Decision 0002, row 4, names `deploy/accept_linux.py`, and section 3 uses it.
5. **What the probe covers.** `deploy/production-readiness.md` says the probe checks a "writable bounded tmpfs", and plan steps 2 and 4 of `deploy/scanner-security-review.md` list the GID, one CPU, a bounded tmpfs and no outbound TCP connection. `deploy/test_container_boundary.py` checks the UID, the interface list, capabilities, no-new-privileges, the memory and PID limits, the three write denials, a write to the tmpfs, and the absence of a Docker socket and of credentials. It does not check the GID, the CPU limit, the size of the tmpfs or an outbound TCP attempt (GL-14, GL-15 and GL-18).
6. **Probe tools.** `deploy/mini-pc-scanner-evaluation.md` lists five tools the image must contain. The comment in `deploy/test_container_boundary.py` lists four and leaves out `touch`, which the probe uses.
7. **Local test counts.** The documents record 52 tests (`deploy/scanner-security-review.md`), 62 (`deploy/mini-pc-scanner-evaluation.md`), 118 and 203 (`deploy/backend-checkpoint.md`), 159 (`deploy/production-readiness.md`), 185 (`deploy/production-operations.md`) and 203 (`deploy/mini-pc-acceptance.md`). Each was true at its checkpoint. None is evidence for a deployment.
8. **Archives.** `deploy/mini-pc-scanner-evaluation.md` asks for an "actual malicious archive" test (GL-32). [ARCHITECTURE.md](../ARCHITECTURE.md), "Security controls", says "no repository archive is fetched or unpacked".
9. **A duplicate Check after a crash.** `deploy/verification-checkpoint.md` records a local test of a restart after Check creation "without creating a duplicate Check". `deploy/README.md`, "Operations", says "a narrow crash window can duplicate a Check". No source says whether a duplicate fails GL-49.
10. **How many times a transient failure is tried.** `deploy/README.md`, "Operations", says transient failures "retry up to eight times". `deploy/backend-checkpoint.md` ("an eight-attempt persisted budget"), `deploy/production-operations.md` ("eight-attempt policy"), [ARCHITECTURE.md](../ARCHITECTURE.md), "Failure handling" ("after 8 attempts it is marked failed"), and the code (`job_store.py`, `MAX_ATTEMPTS = 8`) say eight attempts in total. GL-51 uses eight attempts in total.

### Decided, with no verification in the sources

Decision 0001 answers these with a yes or a no, and no source gives a check for them. They are not rows, because this checklist invents none.

- No inbound ports are open on the host.
- GitHub reaches exactly one HTTPS webhook endpoint, through an outbound tunnel.
- The webhook secret and the App private key are kept only in the host's secret store.
- The webhook secret is readable only by the web listener's account. The sources test the other direction (GL-11). `deploy/check_environment.py --role worker` (GL-10) checks that the worker's environment holds no webhook secret, not who can read the secret where it is stored.
- The App installation is narrowed to the repositories the service scans. GL-38 confirms the scope as the deployment documents describe it.

### Setup the sources require without a check

- The proxy caps each request at 1 MiB, and Uvicorn, Docker and SQLite stay private (`deploy/README.md`, "Install and run").
- The two processes are supervised separately, with restart on failure (`deploy/README.md`, "Install and run").
- Logs are capped, and queue state is never erased during updates (`deploy/README.md`, "Install and run").
- The host is kept separate from other workloads (`deploy/README.md`, "Architecture"; `deploy/mini-pc-acceptance.md`, gate 2).
- The test pull request is "labelled" (`deploy/README.md`, "Required release verification"). No source names the label.
