# Minimum production acceptance gates

No production deployment is approved by local test success. An approved Linux VM can be used before the mini PC arrives; do not install/configure a runtime or transfer secrets without authorization.

1. **Scanner release gate.** Obtain a supported Semgrep distribution permitting the patched dependencies; verify its provenance and audit the complete final Linux image/SBOM. Current latest 1.182.1 still pins affected MCP/OpenTelemetry versions. Record the immutable digest. Do not override dependencies, suppress advisories, or treat containment as remediation.
2. **Approved isolated host.** Provision separate non-root web and worker identities, a queue-only shared group/directory (2770), protected worker-owned PEM and a worker-owned rootless Docker daemon. The web identity must be unable to read the PEM or access the Docker socket. Keep vulnerable labs separate. This setup requires host/security/secret-placement approval.
3. **Real container checks, without App credentials.** With the approved image already present and the worker's rootless Docker connection configured, run:

```sh
PRSEC_SCANNER_IMAGE='APPROVED_IMAGE@sha256:APPROVED_DIGEST' \
  .venv-service/bin/python deploy/accept_linux.py
```

Capture actual identity, mount/network/capability/resource evidence and all 41 rule results. Additionally test OOM/PID exhaustion, timeout/overflow cleanup and host reboot. Exercise cleanup denial/daemon loss: a failed absence check must never produce a pass. If logs contain `container_cleanup_unconfirmed`, inspect the exact generated container name and resolve the orphan/daemon issue under the operator's authority before resuming workload. No such Linux tests have run on this Mac.

4. **Queue migration and role configuration.** Stop intake/worker, verify a WAL-consistent backup, inspect/restore into a new location, quarantine/replay legacy contextless jobs, and preserve Check IDs/cooldowns. Follow [production-operations.md](production-operations.md), then run as each actual role:

```sh
.venv-service/bin/python deploy/check_environment.py --role web
.venv-service/bin/python deploy/check_environment.py --role worker
```

Do not share the combined development environment between roles. Passing these checks does not replace cross-UID denial tests.

5. **Approved ingress and App activation.** Confirm existing repository/installation scope and permissions. Approve the HTTPS destination and placement of existing secrets; verify invalid signatures cannot queue work. Inspect/enable `push` subscription only with approval. Verify base-branch pushes and normal PR lifecycle events are delivered; code support is not subscription evidence.
6. **Authorized live acceptance.** In the confirmed target repository, use an explicitly approved temporary test PR. Verify vulnerable/fixed exact-commit outcomes, base updates, duplicate deliveries, stale cancellation, worker restart/Check reconciliation, transient token/API failures, cooldown and permanent-failure visibility. Do not merge or alter unrelated work. Record the remaining at-least-once recovery limits.

Until these gates pass, the system is locally tested code with unresolved release/runtime/integration gates. Current evidence: 203 local tests and all 15 production-rule compatibility checks passed; GitHub and Docker integration behavior in the local suite is mocked. Running local demos were not restarted or reconfigured.
