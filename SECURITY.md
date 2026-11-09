# Security model

sast-triage runs from the command line and as a GitHub Action. The GitHub App service runs locally; its live deployment is prepared but not complete. For shared or multi-tenant use of the App, run durable mode with the isolated worker in [deploy/README.md](deploy/README.md).

## Trust boundaries

- **Webhook sender:** every event needs a valid HMAC-SHA256 signature over the exact body (constant-time, rotation supported). No secret, no processing.
- **PR author:** repository content is untrusted and never executed. Unsafe archives (traversal, links, special files, duplicates, multiple roots) are rejected, and size limits fail closed.
- **Scanner:** only changed Python, JavaScript and TypeScript files are staged; PR rules, ignore files, Git metadata and credentials are excluded, and `nosemgrep` is ignored. Semgrep runs with metrics off and accepts one local, service-owned rule file outside the scanned tree; registry IDs, `auto` and URLs are refused, so it never downloads rules. Scanner errors cannot pass a check.
- **Command line and GitHub Action:** the scanned checkout is untrusted and never executed. Its Semgrep rules, ignore files and git configuration can't change the scan: external diff and text-conversion helpers and fsmonitor are turned off, symbolic links are not followed, and a `--base` that looks like an option is refused. The Action passes its inputs through environment variables, installs only `requirements-cli.txt` and uses no token.
- **GitHub:** API credentials stay in the parent process; TLS verification stays on. Tests and command-line scans make no GitHub calls.

## Remaining risks

- **Local mode is not an OS sandbox.** Before public use, run the scanner as an unprivileged worker with no egress and strict resource limits.
- Limits reduce, not eliminate, parser and decompression denial of service. Timeouts are per step.
- Local mode keeps jobs in memory: a crash can leave incomplete Checks, and signed replays repeat scans.
- Logs and findings can contain source-derived text; restrict access and retention.
- A passing gate means the rules found no new P1 findings in the scanned Python, JavaScript and TypeScript files. It is not a security certification.
- "Pre-existing" only means the line was not changed; a PR can make an untouched line match. A missing diff marks a file's findings as new. In local mode a push mid-scan can mislabel findings; durable mode cancels such scans.

## Durable mode and dependencies

Durable mode scopes jobs and tokens to one repository, persists Checks, and requires a rootless Docker scanner; gates are in [deploy/README.md](deploy/README.md). `requirements.txt` and `requirements-cli.txt` resolve to Semgrep 1.79.0, and pip-audit reports no known vulnerabilities in either. The newest Semgrep tested, 1.182.1, pins MCP and OpenTelemetry releases with five known advisories, so it is not used. No host or credentials have been provisioned.

## Reporting a vulnerability

Use private vulnerability reporting if enabled, or contact the owner privately. Do not post credentials or exploit details publicly. No response time is promised.
