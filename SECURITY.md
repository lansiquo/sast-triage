# Security model

sast-triage runs locally and in its own CI; live GitHub deployment is prepared but not complete. For shared or multi-tenant use, run durable mode with the isolated worker in [deploy/README.md](deploy/README.md).

## Trust boundaries

- **Webhook sender:** every event needs a valid HMAC-SHA256 signature over the exact body (constant-time, rotation supported). No secret, no processing.
- **PR author:** repository content is untrusted and never executed. Unsafe archives (traversal, links, special files, duplicates, multiple roots) are rejected, and size limits fail closed.
- **Scanner:** only changed Python files are staged; PR rules, ignore files, Git metadata and credentials are excluded, and `nosemgrep` is ignored. Scanner errors cannot pass a check.
- **GitHub:** API credentials stay in the parent process; TLS verification stays on. Tests and the offline demo make no GitHub calls.

## Remaining risks

- **Local mode is not an OS sandbox.** Before public use, run the scanner as an unprivileged worker with no egress and strict resource limits.
- Limits reduce, not eliminate, parser and decompression denial of service. Timeouts are per step.
- Local mode keeps jobs in memory: a crash can leave incomplete Checks, and signed replays repeat scans.
- Logs and findings can contain source-derived text; restrict access and retention.
- A green check means the rules found no new P1 findings in changed Python files. It is not a security certification.
- "Pre-existing" only means the line was not changed; a PR can make an untouched line match. A missing diff marks a file's findings as new. In local mode a push mid-scan can mislabel findings; durable mode cancels such scans.

## Durable mode and dependencies

Durable mode scopes jobs and tokens to one repository, persists Checks, and requires a rootless Docker scanner; gates are in [deploy/README.md](deploy/README.md). The developer environment (`requirements.txt`) has known dependency advisories, and the tested Semgrep 1.182.1 has five unresolved advisories. No host or credentials have been provisioned.

## Reporting a vulnerability

Use private vulnerability reporting if enabled, or contact the owner privately. Do not post credentials or exploit details publicly. No response time is promised.
