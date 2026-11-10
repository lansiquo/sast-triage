# Scanner dependency review

**Status: unresolved; deployment gate remains closed.** No vulnerability ignore list, dependency override, package metadata edit, or risk waiver was applied.

## Supported-version investigation

Official PyPI metadata identifies `semgrep==1.182.1` as the latest stable release. That release and the seven preceding stable releases inspected (1.182.0, 1.181.1, 1.181.0, 1.180.0, 1.179.0, 1.178.0, 1.177.0) require `mcp==1.29.0` and `opentelemetry-api~=1.37.0`.

The patched MCP 1.x release is 1.30.0. OpenTelemetry API's fix is 1.45.1. A pip dry run requesting the official Semgrep release together with both patched dependencies fails with `ResolutionImpossible`. In addition to MCP's exact pin, the OpenTelemetry constraint excludes 1.45.1 (`~=1.37.0` means >=1.37.0 and <1.38.0). Its associated SDK/exporter pins also require coordinated upstream updates. Forcing these packages with `--no-deps` would not be a supported remediation.

A new **scanner-only** environment was created independently of the service and original developer environments. It installs the official Semgrep package with its supported dependency graph. `pip check` passes, but the vulnerability audit still finds the five advisories below. The separate updated service environment has no known vulnerabilities in its current audit. Thus the scanner findings are not artifacts of the previously observed FastAPI/OpenTelemetry conflict.

## Exact remaining advisories and reachability assessment

| Package | Advisory | Affected behavior | Assessment for this project |
| --- | --- | --- | --- |
| mcp 1.29.0 | [CVE-2026-59951 / GHSA-84m7-p3x7-pcfv](https://github.com/advisories/GHSA-84m7-p3x7-pcfv) | Unbounded retained sessions in stateful Streamable HTTP servers | No MCP server is started by the scan-only command. |
| mcp 1.29.0 | [CVE-2026-116685 / GHSA-5h93-6whr-6q8j](https://github.com/advisories/GHSA-5h93-6whr-6q8j) | MCP HTTP client redirects can forward custom headers and bodies across origins | No MCP HTTP client or remote MCP endpoint is configured. |
| mcp 1.29.0 | [CVE-2026-116684 / GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23) | MCP bearer authentication accepts tokens intended for another resource | No MCP HTTP server or its token verifier is exposed. Note: the upstream fix also requires the documented audience-validation configuration when using that server feature. |
| mcp 1.29.0 | [CVE-2026-116686 / GHSA-rwrf-2pqf-9j8j](https://github.com/advisories/GHSA-rwrf-2pqf-9j8j) | MCP tool-result validation follows remote/file schema references | No MCP tool-result validation occurs in the reviewed scan path. |
| opentelemetry-api 1.37.0 | [CVE-2026-114603 / GHSA-xcq7-p3pf-p88h](https://github.com/advisories/GHSA-xcq7-p3pf-p88h) | Excessive CPU parsing malicious incoming `tracestate` values | The scanner is a CLI, not an HTTP listener. Its environment is allowlisted and excludes trace propagation variables. The inspected Semgrep telemetry extraction constructs `traceparent` from environment values, not inbound webhook `tracestate`. The independently patched web service uses OpenTelemetry API 1.45.1. |

These are source-based reachability assessments for the exact command/environment, **not proofs of unreachability and not waivers**. The packages are still installed and vulnerable. Rootless Docker, denied network egress and resource caps would add containment but do not patch them. Container containment has not yet been tested on a real daemon.

MCP advisories list fixes in 1.30.0 or 2.2.0. Switching this package to MCP 2.x would also violate Semgrep's dependency contract. The OpenTelemetry fix is >=1.45.1.

## Native CLI alternative examined

The installed Semgrep entrypoint can dispatch to its native engine, but its own source says commands may fall back to the Python implementation. Calling or extracting the native binary is therefore not established as a supported drop-in package remediation. An official minimal/native image could be evaluated separately only after verifying feature parity, fallback behavior, provenance, licensing, complete image/SBOM audit, and Linux isolation tests. No alternate scanner or image was silently selected.

## Reproduction

Use the isolated investigation folder kept outside the repository on the evaluation Mac:

```sh
.venv-scanner/bin/python -m pip check
SEMGREP_BIN="$PWD/.venv-scanner/bin/semgrep" make check PY=.venv-service/bin/python
```

This explicitly tests current Semgrep 1.182.1 rather than the Homebrew executable. The original project environment and global tools are unchanged. Audit reports are saved alongside the investigation folder as `pr-reviewer-scanner-only-audit.json` and `pr-reviewer-service-reaudit.json`. No secrets are included in those reports.

## Verification result

The current scanner-only environment passes `pip check`. With its Semgrep 1.182.1 executable explicitly selected, all 52 tests pass and both real scanner fixtures produce the expected results (two high-severity findings and zero findings, respectively). The fresh scanner audit still reports five vulnerabilities in two packages; the fresh service audit reports none. One test-client deprecation warning remains in the updated service environment.

## Remaining options

1. Prefer a supported upstream Semgrep release that permits patched MCP/OpenTelemetry versions; rerun dependency resolution, the complete tests and fixtures, and the audit before deployment. No such release was found in this investigation.
2. With an explicit architecture decision, evaluate a supported standalone/native distribution or another scanner. This needs compatibility, provenance and vulnerability verification; it is not currently a verified replacement.

Do not deploy the present scanner package by suppressing its findings, forcing incompatible dependencies, or treating the scan-only reachability assessment as a silent waiver.

## Rootless container verification plan (not executed)

Prerequisites: an approved Linux test host with an already configured rootless Docker daemon; an immutable scanner image that has passed dependency and OS/SBOM audits. Do not install Docker or change security settings as part of this test without approval.

1. Confirm `docker info` reports rootless mode. Confirm the image digest matches the approved audited artifact. Worker startup must reject a non-rootless daemon, missing image, or mutable tag.
2. Use disposable fixture mounts and the exact `docker_scan_command` controls. Inspect the running container: network mode `none`, UID/GID 65532, read-only root filesystem, all capabilities dropped, no-new-privileges, one CPU, 768 MiB memory, 128 PIDs, bounded tmpfs, source/rules mounts read-only, and no Docker socket/home/PEM/env mounts.
3. Probe filesystem permissions inside the disposable container: writes to root and source/rules mounts must fail; writes only to the bounded tmpfs may succeed. Confirm no service credentials appear in its environment or mounts.
4. Confirm no external routes/interfaces or successful outbound TCP connection from the container. Do not use real credentials or private targets in the probe.
5. Run vulnerable and clean fixtures and compare normalized rule IDs, exact file/line annotations and conclusions with the host fixture results. Include malformed Python and invalid rules to prove incomplete scans cannot pass.
6. Exercise output overflow and subprocess timeout. Confirm a failed result and that the named container is removed, including when the Docker client times out. Confirm memory/PID-limit termination cannot produce a successful check.
7. Restart the worker during a scan and around remote Check creation. Confirm the durable job is recovered, the exact external ID/App ID is reconciled, and only the intended repository/commit is targeted. This last step requires the separately approved live GitHub integration test.
8. Preserve the image digest, audited package versions, test outputs and cleanup evidence. Only then reconsider the deployment gate.

Sources: [official PyPI release metadata](https://pypi.org/pypi/semgrep/1.182.1/json), [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference), and the individual upstream advisories linked above.

## Semgrep retained (latest checkpoint)

The user selected Semgrep; alternative-scanner evaluation is deferred. Official PyPI metadata was rechecked: 1.182.1 remains latest and still pins MCP 1.29.0 and OpenTelemetry API ~=1.37.0. Fresh isolated-environment audits again found five scanner advisories in those two packages and no known service-environment vulnerabilities. No incompatible overrides or vulnerability waivers were applied. The trusted-fixture local GUI works with the existing Semgrep default; this does not clear production deployment.
