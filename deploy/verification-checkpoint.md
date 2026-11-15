# Local verification checkpoint

The official Opengrep v1.33.0 macOS ARM64 artifact still has **incomplete signature verification**. The checksum passed before Cosign ran. Exact workflow identity and GitHub Actions issuer were enforced by `verify_opengrep_signature.py`; Cosign exited 1 after four attempts because Rekor TLS negotiation timed out. An independent request to the official Rekor endpoint also timed out. No TLS, identity, issuer, or transparency-log checks were disabled.

The official release asset list contains no bundle/attestation, and GitHub's public attestation endpoint for the artifact digest returned HTTP 404. Those observations do not prove a bad signature; they leave verification blocked. The installed/default scanner is unchanged. Since [decision 0002](../docs/decisions/0002-durable-scanner.md) (2026-11-12) did not choose Opengrep, this signature check is not a go-live step; a checksum alone is still not signature clearance.

`tests/test_recovery_boundaries.py` adds local checks for:

- Worker restart after remote Check creation but before saving its ID, without creating a duplicate Check.
- Worker retry after pipeline/completion failure, reusing the Check ID and withholding private exception messages from logs.
- Concurrent SQLite claims returning each job only once.
- A PR head changing during download/preparation: cancel before scanning and remove temporary source files.
- Multiple archive roots and truncated file payloads failing closed.

These exercise real SQLite connections, local file locks, and temporary directories. GitHub calls and Docker preflight are mocked. They do not certify a real container or remote GitHub integration.

Pending mini-PC gates: provision the dedicated Linux VM, execute `test_container_boundary.py` against the final digest-pinned rootless image, audit that final image and its Semgrep 1.79.0 distribution and verify its provenance, then obtain approval for credential placement and for the tunnel the VM opens outbound, with no inbound port ([decision 0001](../docs/decisions/0001-hosting-and-trust.md)). The five dependency advisories of Semgrep 1.182.1 remain unresolved, and that version is not used; see `scanner-security-review.md`. No scanner switch, hosting, tunnel, credential transfer, or GitHub mutation occurred during this checkpoint.
