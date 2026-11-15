# Trusted controller and untrusted scanner boundaries

## Credential ownership

- **Web listener (trusted, separate Linux UID):** receives the webhook secret and verifies HMAC. It queues normalized identifiers. It must have no App PEM access, no installation token, and no access to the worker's home or rootless Docker socket.
- **Worker/controller (trusted, separate Linux UID):** reads the App PEM, mints narrowly scoped installation tokens, fetches repository data, launches the container, and writes GitHub Checks. Only this component holds the App PEM and installation tokens.
- **Docker CLI (trusted controller helper):** is a host subprocess, not the untrusted scanner. It needs the worker's rootless socket/context to create the container. Its allowlisted environment excludes the App PEM, PEM path, webhook secrets and tokens. Its host filesystem authority is still the worker's; do not treat this helper as sandboxed.
- **Scanner (untrusted parser boundary):** only receives selected source files and service-owned rules through two read-only mounts. No App PEM, `.env`, home directory, repository metadata, or Docker socket is mounted. Only fixed nonsecret scanner environment variables are passed. Network is disabled, capabilities dropped, privileges constrained, and resources bounded.

The mini PC deployment must run the web and worker as different OS users; sharing a queue group does not authorize sharing secrets or Docker access. `PRSEC_SHARED_STATE=1` supports the queue's mode-660 database under an operator-provisioned mode-2770 directory. Cross-UID permissions and SQLite WAL/SHM operation still require actual Linux tests.

## Enforced code gates

Both worker startup and the scanner runner reject an unsandboxed local backend in `PRSEC_MODE=durable`. A misspelled backend also fails instead of silently selecting a host process. Local mode exists only for fixture/development use. Its host subprocess has an allowlisted environment and temporary staging directory, but these are **not filesystem or network isolation**. Do not scan hostile live repositories with credentials available on that host merely because the environment test passes.

The deployment scanner boundary must be the container. A parser compromise in local mode could access files readable by that OS user even when their paths are omitted from its environment. We do not claim otherwise.

## Verified tests

- A real, controlled scanner subprocess is launched with sentinel values seeded for the App PEM, PEM path, both webhook-secret variables, explicit installation token, GitHub/GH tokens and Semgrep token. It asserts every value's variable is absent, no repository `.env`/ignore/rule files were staged, only the requested source is present, and HOME is the staging directory.
- A separate Docker-command unit test seeds the same variables, verifies they are absent from the host Docker launch/cleanup environment, and checks that the container command has exactly two read-only mounts targeting `/scan` and `/rules.yaml`, with no secret environment arguments.
- A regression test confirms durable mode refuses the host scanner backend before invoking any scanner.

The Docker-command test is **mocked**. Actual container filesystem/namespace/network boundaries and host cross-user PEM/socket denial remain unrun until the dedicated mini PC Linux VM is provisioned. `test_container_boundary.py` is prepared for those checks; it refuses to treat a non-Linux/non-rootless system as a successful test.

## Signature verification checkpoint

Artifact: official Opengrep v1.33.0 macOS ARM64 binary, SHA-256 `87d38a3ca198694a651e723b503e3ff8b0547429b4b9dfa2946f75fc43bb1962`.

Expected keyless certificate identity:

`https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.0`

Expected issuer: `https://token.actions.githubusercontent.com`.

The identity and source commit match the official release workflow and certificate fields. This observation alone is not certificate/transparency verification. The ordinary Cosign check with these exact values failed to complete at `https://rekor.sigstore.dev/api/v1/log/entries/retrieve` with TLS handshake timeouts. An independent read of the official Rekor endpoint also timed out. No signature mismatch was reported; the outcome is **incomplete verification**, not a pass.

The official release API returned no bundle/attestation assets. The public GitHub attestation lookup for this digest returned 404. The pinned upstream workflow publishes separate `.sig` and `.cert` files using `cosign sign-blob`, not an offline bundle. No supported offline verification material was found. We did not fabricate a bundle, omit transparency verification, bypass TLS, or use a different untrusted log.

Since [decision 0002](../docs/decisions/0002-durable-scanner.md) (2026-11-12) did not choose Opengrep, this check is not a go-live step; the record above is kept as it was. `verify_opengrep_signature.py` stays in the repository: on a functioning connection, supplying the artifact, certificate, signature and independently verified release SHA-256, it preserves exact identity/issuer checks and reports success only after Cosign exits successfully. A verified macOS binary would not verify a Linux artifact or the final container image, which is still audited separately (gate 3 in [README.md](README.md#approval-gates)).

References: [upstream pinned signing workflow](https://github.com/opengrep/opengrep/blob/641c730dd99e028ee63d2f3ab3c70a7adce4b199/.github/workflows/rolling-release.yml), [Sigstore verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).
