# Production backend checkpoint

These changes affect the real webhook/worker path, separately from the local showcase. No GitHub writes, deployment, or credential changes were performed during validation.

## Concrete fixes

- **Respect GitHub rate limits across the queue.** Previously a limited job retried on ordinary 10–300 second backoff and the worker could immediately run a different job against the same installation. HTTP 429 and explicit 403 rate-limit headers now produce a safe structured error. Retry-After and exhausted primary-limit reset times determine a minimum delay. A persistent SQLite worker_backoff record blocks all claims until that time, including after restart. Malformed delays fall back to at least 60 seconds. A rate limit encountered during preparation/scanning leaves the Check available for later recovery rather than attempting another completion API request immediately.
- **Cancel results that became stale during scanning.** The worker pipeline rechecks the PR after Semgrep returns. Closing the PR or changing its head now cancels the result rather than publishing the completed scan as current. Earlier checks also recognize closed PRs.
- **Fail closed on missing source and malformed file listings.** Explicitly removed files are excluded from GitHub’s file list; other changed Python files must exist in the immutable snapshot. A missing file or malformed response cannot turn into a neutral or clean scan.
- **Keep private exception messages out of logs.** Authentication refresh, token acquisition, Check creation and payload-parsing errors log only exception types.

Historical validation: `make check` passed 118 tests plus the original live CLI scanner demo. New tests exercise HTTP rate-limit handling with controlled responses, real persistent SQLite cooldown across restart and multiple jobs, the actual worker loop, deferred completion, post-scan head changes/closure, missing snapshots, malformed/deleted file lists, and secret-sentinel logging. GitHub calls and Docker preflight remain mocked; this is not live GitHub end-to-end or real container-boundary validation.

GitHub rate-limit behavior follows https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#handle-rate-limit-errors-appropriately . No sleeping network call is added to a webhook handler; the worker's persisted scheduling handles the wait.

## Prioritized remaining gates

1. Resolve the five Semgrep dependency advisories with a supported upstream version/distribution. Current inspected 1.182.1 pins exclude the patched MCP/OpenTelemetry versions. Keep the separately audited service environment isolated; do not force incompatible overrides or waive findings.
2. Run `deploy/test_container_boundary.py` on the approved Linux VM with the final digest-pinned rootless scanner image. Audit that image and execute scanner fixtures there. Existing harness and runbook remain prepared; actual runtime isolation is unverified on this Mac.
3. Verify real GitHub installation scope, webhook delivery/recovery and exact-commit Check behavior in the approved target repository when deployment credentials/network placement is authorized. No mocked test clears this gate.


## Lifecycle and failure-recovery follow-up

Same-head reopen events now create a new job, while redelivery of that event deduplicates using its stable delivery ID. Base SHA and branch name participate in identity and are checked before download, after file listing, and after scanning. Metadata-only edits do not create another run. The later operations update quarantines active legacy jobs before credential access and handles authenticated base-push fanout when the App is subscribed to push events; see [production-operations.md](production-operations.md).

Permanent HTTP/request and scanner infrastructure failures now become visible failed jobs. Transient failures have an eight-attempt persisted budget, including recovery from worker interruption. Readiness reports degraded queue status, safe terminal logs identify the job/reason, and `manage_jobs.py` provides local inspection and explicit recovery preserving the Check ID. Successful analysis with security findings is distinct from infrastructure failure. See [the runbook](README.md) for recovery and remaining remote-Check limitations.

Tests first reproduced six lifecycle/retry failures (one existing behavior already passed). The new 13-test lifecycle suite covers reopen redelivery/restart, base changes, metadata deduplication, bounded retries/crash recovery, permanent errors, base-context forwarding, concurrent recovery, Check reuse, and scanner-error versus vulnerability outcomes. Final `make check`: **118 passed**, followed by the real vulnerable/clean CLI fixture scans; `git diff --check` passed. GitHub API calls remain controlled mocks, while SQLite persistence and concurrency run against real local databases. The existing local GUI remains unchanged and responds at `http://127.0.0.1:8765/`.

Delivery identity follows [GitHub webhook best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks): a redelivery retains the original delivery ID.

## Fail-closed follow-up

Three concrete gaps were reproduced with failing tests before fixing them:

- Unknown scanner severity previously normalized to LOW and could disappear under a HIGH severity floor, yielding an empty result. The runner now validates finding identity, location, severity and message shape before normalization/filtering. Malformed evidence raises a scan error; legitimate INFO filtering remains supported.
- A temporary HTTP 503 during installation-token refresh was swallowed behind the original HTTP 401, causing the worker to classify the job as permanently unauthorized. Request failures during refresh now propagate with their real status/type, so transient failures enter persisted backoff. Logs still omit response/error bodies.
- Docker cleanup failures were ignored after a successful scan. Cleanup now requires a successful removal or a successful exact-name listing confirming the auto-removed container is absent. A daemon error, remaining container or cleanup timeout fails the scan and logs only its generated container name. This confirms absence only when the daemon answers; it does not claim to kill a container when Docker is unavailable. An unconfirmed cleanup requires operator investigation before resuming production workload.

Final `make check`: **203 passed**, followed by expected vulnerable/clean real CLI scans. All **15 production rules** also passed with the existing isolated official Semgrep **1.182.1**, including suppression resistance and clean comparison. `git diff --check` passed. New tests include malformed evidence, valid severity-floor behavior, refresh-outage SQLite retry persistence and cleanup success/absence/failure/timeout. Docker API interactions remain mocked; no real isolation claim is made.

Official PyPI was checked once during this follow-up: latest remains 1.182.1 with MCP ==1.29.0 and OpenTelemetry API ~=1.37.0. No new compatible supported remediation was available; no dependency override or fresh exhaustive audit is claimed. Both running local labs were left untouched. The concise next-host gates are in [mini-pc-acceptance.md](mini-pc-acceptance.md).
