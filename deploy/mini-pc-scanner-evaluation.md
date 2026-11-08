# Mini PC deployment preparation and scanner evaluation

## Current decision

Wait for the mini PC. Keep the existing GitHub App and intended `lansiquo/sast-triage` installation target. No paid hosting, GitHub Actions redesign, tunnel, new access grant, credential transfer, or public exposure has occurred.

## Evaluated alternative: Opengrep v1.33.0

Evaluated from the [official v1.33.0 release](https://github.com/opengrep/opengrep/releases/tag/v1.33.0). Source commit: `641c730dd99e028ee63d2f3ab3c70a7adce4b199`. The official macOS ARM64 complete release executable was downloaded into the project investigation folder, not installed globally. Its SHA-256 matches GitHub release metadata:

`87d38a3ca198694a651e723b503e3ff8b0547429b4b9dfa2946f75fc43bb1962`

Its official source dependency declaration includes neither MCP nor OpenTelemetry. Thus this distribution offers a path that avoids the two dependency families responsible for the five unresolved Semgrep findings, rather than overriding Semgrep's version constraints.

**Compatibility passed:** the official complete executable runs both demo fixtures and all 15 embedded rules. An inline `nosemgrep` comment no longer suppresses the MD5 finding. The adapter omits Semgrep's unsupported `--metrics=off` argument only when Opengrep is explicitly selected; it retains disabled version checks, one scanner job, disabled inline ignores, a 1 MiB per-file bound, required target-coverage reporting, timeouts, and fail-closed handling. The default remains Semgrep.

**Audit limitations remain explicit:** a separately resolved source dependency graph had no known findings among its auditable Python dependencies, but pip-audit skipped the locally built `opengrep` package because that version is not on PyPI. The source-only wheel could not execute without upstream-generated interface files; its audit is not an audit of the runnable self-contained release binary. The official binary includes compiled/bundled components which require a release SBOM/native/OS audit on the final Linux image. Do not report the alternative as fully vulnerability-cleared yet.

**Artifact provenance:** the executable checksum is verified. Cosign certificate/signature verification was attempted twice with an isolated checksum-verified Cosign tool; both attempts failed to complete because the Rekor transparency-log endpoint timed out during TLS. No transparency-log, signature, certificate, or TLS requirement was bypassed. Complete verification against the official release workflow before deployment.

Recommendation: retain Opengrep 1.33.0 as the preferred candidate for the mini PC image, contingent on complete signature verification, Linux image/SBOM audit, and actual container tests. Switching the deployment's scanner remains an explicit choice. The current Semgrep package's original five findings remain unresolved and are not waived.

## Concrete code improvements

- Reject files larger than 1 MiB before scanner invocation.
- Require the scanner to report every requested source file as scanned; silently skipped files cannot produce a green Check.
- Disable inline `nosemgrep`/`nosem` suppression for service-owned security rules.
- Bound scanner parallelism to one job and explicitly set its per-target byte limit.
- Add an explicit, allowlisted Opengrep adapter; no automatic engine switch.
- Add an opt-in shared SQLite mode for separate web and worker UIDs. Only the queue is shared; credentials and rootless Docker access remain worker-only.
- Increase scanner writable tmpfs to 512 MiB because the official macOS self-contained executable expands to about 244 MiB before scan work. The Linux artifact's actual peak must still be measured. The 768 MiB container memory limit remains a release-test gate, not a guarantee that all repository sizes fit.

## What was actually tested

The local suite includes real subprocess execution proving that repository `.env`, `.semgrepignore`, and `.semgrep.yaml` files are not staged and credential environment variables do not reach the child. It also exercises real subprocess output overflow and timeout termination, plus archive/path/symlink rejection, authentication, queue recovery and deduplication.

The fake scanner used for process-isolation tests checks only staging and environment boundaries. A normal host subprocess is **not** a filesystem/network sandbox. Unit tests of Docker argument construction and rootless-daemon rejection do **not** prove container isolation.

The actual Opengrep and Semgrep 1.182.1 executables both passed the 15-rule compatibility fixture in local subprocesses. These fixture source files are never executed.

## Reproduce local evaluations

Use the isolated investigation folder kept outside the repository on the evaluation Mac:

```sh
PRSEC_SCANNER_COMMAND=opengrep \
SEMGREP_BIN="$PWD/opengrep-official/opengrep_osx_arm64" \
make check PY=.venv-service/bin/python

PRSEC_SCANNER_COMMAND=opengrep \
SEMGREP_BIN="$PWD/opengrep-official/opengrep_osx_arm64" \
.venv-service/bin/python deploy/validate_scanner.py
```

For the existing Semgrep comparison, use `PRSEC_SCANNER_COMMAND=semgrep` and `SEMGREP_BIN="$PWD/.venv-scanner/bin/semgrep"` instead. No global/Homebrew packages were modified.

## Future mini PC prerequisites

- Dedicated supported Linux VM, isolated from intentionally vulnerable labs; estimate 2 vCPUs, 4 GiB RAM, 20 GiB persistent disk. One worker scans one job at a time. Revisit resources after real Linux measurements.
- Two Linux service users: `prsec-web` with only the webhook secret and queue access; `prsec-worker` with the existing App PEM, queue access and its own rootless Docker daemon. Shared queue group/directory mode 2770; database mode 660; umask 0007. Validate WAL/SHM cross-user access on Linux.
- Rootless Docker with functional cgroup v2 CPU/memory/PID controls. Do not expose its socket to the web service or scanner container. No Docker installation or host security change was made on the Mac.
- Persistent SQLite state and backups, worker restart supervision, queue-age/error monitoring. No horizontal replicas or network filesystem for this design.
- An approved, digest-pinned Linux scanner image with signature/provenance, complete SBOM and vulnerability review. For explicit Opengrep selection set `PRSEC_SCANNER_COMMAND=opengrep`; runtime image pulling is disabled.
- Approval before transferring the existing App PEM or webhook secret to the VM. Reuse App ID 1776205 and installation 80788483. Runtime tokens request only Contents read, Pull requests read and Checks write for `lansiquo/sast-triage`. No permission expansion is needed; the App credential itself retains its existing broader authority.
- An independently approved ingress/TLS plan before changing the Smee webhook. No tunnel, firewall, routing or DNS changes are part of this preparation.

## Actual rootless boundary test — prepared, not run

After provisioning is approved and the image is audited, set `PRSEC_SCANNER_IMAGE` to its immutable digest and configure the worker's existing rootless `DOCKER_HOST`. The final test image must contain `/bin/sh`, `id`, `grep`, `ls`, and `touch` for the probe; missing tools are a failed/unrun test, not a pass.

```sh
.venv-service/bin/python deploy/test_container_boundary.py
PRSEC_SCANNER_BACKEND=docker .venv-service/bin/python deploy/validate_scanner.py
```

The boundary probe refuses non-Linux and non-rootless environments. It checks real container UID, no external network interfaces, effective capabilities, no-new-privileges, cgroup memory/PID limits, read-only root/source/rules mounts, absence of host marker/credential environment, and absence of a Docker socket. It cleans up its named container. Follow with actual malicious archive, scanner output/timeout, memory-limit termination and worker-crash recovery tests. Verify the Linux cross-UID queue and web-user denial of PEM/socket access separately.

**Still unrun:** actual Docker/container boundaries, final Linux image/native audit, successful transparency-log signature verification, cross-UID Linux permissions, mini-PC resource measurements, and live GitHub webhook/Check delivery. Deployment is not complete until these gates pass.

## Exact-identity verification and credential boundary follow-up

See [trust-boundaries.md](trust-boundaries.md). An exact release-workflow identity retry remained blocked by Rekor TLS timeouts; no official offline bundle was found. The suite now has 62 passing tests, including sentinel checks for every App/token variable and a durable-mode rejection of host scanning. The default scanner remains unchanged.
