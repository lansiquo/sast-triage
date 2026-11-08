# Security model

sast-triage v1.0 runs locally and in its own CI; live GitHub deployment is prepared and not yet complete. Run it as a shared or multi-tenant scanner only in durable mode, with the isolated worker described in [deploy/README.md](deploy/README.md).

## Trust boundaries

- **Webhook sender:** HMAC-SHA256 over the exact body is required, including ping events. No secret means no processing. Constant-time comparison supports rotation. Signed content is still validated before building GitHub API paths.
- **PR author:** repository content is untrusted. Archives reject traversal, absolute paths, links, special files, duplicate entries, multiple roots, excessive members, and excessive expanded size. Downloads have a compressed-size cap. Repository code is never executed.
- **Scanner:** only changed Python files are copied into a fresh scan directory. PR rules, ignore files, Git metadata and application credentials are excluded. Trusted rules are owned by this service, and `nosemgrep` comments are ignored. Engine errors, killed processes, malformed output, and reported parse errors cannot turn into a passing check.
- **GitHub:** API credentials stay in the parent process. HTTPS certificate verification remains enabled. No test is allowed outbound HTTP. The offline demo does not mint tokens, create Checks, post comments, or fetch repositories.

## Remaining risks

Semgrep is a parser handling hostile source; a subprocess is not a security sandbox. Use a separate unprivileged worker with denied egress and strict resource limits before public use. Limits reduce archive abuse but do not eliminate decompression or parser denial of service. HTTP timeouts do not establish an end-to-end pipeline deadline. Background tasks are in-memory, have no persistent delivery deduplication, and may leave incomplete Checks after a crash. Signed replays can repeat scans. Logs and findings may contain source-derived text; restrict access and retention. Avoid loading secrets into development environments used for arbitrary tools.

Rules cover selected Python patterns and can yield false positives or miss vulnerabilities. A green result means these rules found no new P1 findings in the scanned changed Python files; other findings are still annotated. It is not a security certification.

Triage labels come from GitHub's diff for the pull request. When a file's diff is missing or unreadable, every finding in it counts as new, so a bad diff can only over-report. "Pre-existing" only means the flagged lines were not changed: a pull request can make an untouched line match (for example by adding an import), and that finding is labelled pre-existing and does not fail the check, so reviewers should still read pre-existing notices in touched files. In the default local mode the diff is fetched after the snapshot, so a push in between can mislabel findings on the superseded commit; durable mode re-checks the head commit and cancels such scans.

## Reporting

Use the repository's private vulnerability reporting facility if enabled, or contact the repository owner through an established private channel. Do not post credentials or exploit-sensitive repository data in a public issue. No response SLA is currently promised.

## Deployment preparation

An opt-in durable mode scopes jobs and ephemeral installation tokens to the configured repository, persists/reconciles Checks, and requires a rootless Docker scanner worker. See [deploy/README.md](deploy/README.md) for the controls and unverified deployment gates. The risks above describe the default local mode; durable mode is intended for production once the approval and release gates in that guide are met on the target host. The developer environment from `requirements.txt` has known dependency advisories, and the tested Semgrep 1.182.1 package has five unresolved advisories. No host or credentials have been provisioned.
