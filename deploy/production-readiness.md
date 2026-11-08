# Production readiness checkpoint

The mini PC itself is not a technical dependency. An approved Linux VM with the required separation and rootless runtime can validate the same controls. No host was installed, started or reconfigured during this checkpoint.

## Verified components and blockers

| Component | Current evidence | Remaining gate |
|---|---|---|
| Webhook, durable queue, recovery and reporting | Full current suite passed with isolated service dependencies and official Semgrep 1.182.1; GitHub calls use controlled mocks, SQLite uses real local databases | Real installation delivery, exact-commit Checks and remote crash recovery still unverified |
| Production rules | All 15 service-owned rules detect their fixtures; nosemgrep cannot suppress MD5; clean comparison passes | Repeat on final audited Linux image |
| Scanner package | Isolated Semgrep 1.182.1 has MCP 1.29.0 and OpenTelemetry API 1.37.0 | Five known advisories still apply; no compatible supported latest release found |
| Host containment | Docker, Colima and Lima CLIs are installed; selected desktop-linux daemon is unreachable, Colima reports stopped, Lima lists no instance | An approved running **rootless Linux** Docker runtime; ordinary Docker Desktop startup alone is not proof of this requirement |
| Deployment configuration | Existing App ID 1776205, existing PEM path, and plural GITHUB_WEBHOOK_SECRETS configuration are present locally; no values printed | Approved target-specific durable settings, separate service identities, protected state, audited image digest and approved HTTPS ingress |
| Demo | Trusted fixtures only, host scanner resolves to existing Homebrew Semgrep 1.133.0 | Demo is not production validation and is not the proposed production scanner environment |

The configured deployment example targets `lansiquo/sast-triage`, installation `80788483`. Those are existing configuration identifiers, **not a fresh assertion that the live installation/permissions still match**. No App JWT or installation token was created for this inspection; no authenticated GitHub calls or remote writes occurred. Existing source requests installation tokens limited to the selected repository with contents:read, pull_requests:read and checks:write. If that installation lacks these permissions, a separately approved permissions change would be needed; it was not assumed or performed.

## Dependency evidence

Official current PyPI metadata still reports Semgrep 1.182.1 with `mcp==1.29.0` and `opentelemetry-api~=1.37.0` (plus matching SDK/exporter constraints). Existing isolated installed versions match. These are incompatible with the patched MCP 1.30.0 and OpenTelemetry API 1.45.1. No packages were overridden or upgraded.

The five existing GitHub advisory records were fetched again without authentication. None was withdrawn; affected ranges still include the installed versions:

- MCP: CVE-2026-59951 / GHSA-84m7-p3x7-pcfv; CVE-2026-116685 / GHSA-5h93-6whr-6q8j; CVE-2026-116684 / GHSA-w4fh-qvv9-3v23; CVE-2026-116686 / GHSA-rwrf-2pqf-9j8j. Patched 1.x version: 1.30.0.
- OpenTelemetry API: CVE-2026-114603 / GHSA-xcq7-p3pf-p88h. Patched version: 1.45.1.

This checkpoint revalidates those known advisories; it is not a fresh exhaustive environment/OS/SBOM audit. The separate service environment has OpenTelemetry API 1.45.1. Its earlier clean audit is historical, not a guarantee of today's complete dependency graph. See [scanner-security-review.md](scanner-security-review.md) for sources and reachability limitations. Containment does not patch a vulnerable dependency.

## Minimum prerequisite and executable next checks

Needed: approval/access to a Linux test VM with an already configured rootless Docker daemon and the final approved audited scanner image preloaded by digest. Creating a VM, starting/installing runtime services or changing host security settings requires the user's approval. No paid host or mini-PC purchase is required for the tests themselves.

On that approved host, as the intended unprivileged worker user, with the project and service environment present:

```sh
# Must report Linux and rootless security options; do not proceed otherwise.
uname -s
docker info --format '{{json .SecurityOptions}}'
# Set this to the actual approved, audited image digest; do not use a mutable tag.
export PRSEC_SCANNER_IMAGE='APPROVED_IMAGE@sha256:APPROVED_DIGEST'
export PRSEC_MODE=durable
export PRSEC_SCANNER_BACKEND=docker
export PRSEC_LOAD_DOTENV=0
.venv-service/bin/python deploy/test_container_boundary.py
.venv-service/bin/python deploy/validate_scanner.py
```

The first harness checks actual UID, network namespace, capabilities/no-new-privileges, memory/PID limits, read-only mounts, writable bounded tmpfs and lack of secret/socket mounts. It requires the probe tools listed in its source. The second checks actual scanner compatibility. Neither alone clears cross-user PEM/socket permissions, all resource-exhaustion cases, complete image audit, or live GitHub recovery: execute the additional [release checks](README.md#required-release-verification) and [trust-boundary plan](trust-boundaries.md).

For live integration, approve the target host/HTTPS destination and secure placement of existing secrets, verify current App installation scope, then authorize the labelled temporary test PR in the intended repository. No new App, expanded grants or token creation were performed here. Until then, remote integration remains unverified, rather than presumed broken.

## Latest local validation

The complete current suite ran from the actual project with the existing isolated service Python and explicitly selected official Semgrep 1.182.1: **159 passed**, one Starlette test-client deprecation warning. The original vulnerable/clean CLI scans passed. Separately, `deploy/validate_scanner.py` passed all **15 production rules**, suppression resistance and clean comparison. No real Docker boundary or live GitHub tests ran. No new backend defect was established in this targeted inspection, so no speculative production refactor was made.
