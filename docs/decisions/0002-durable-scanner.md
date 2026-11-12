# Decision 0002: the scanner for durable mode

- Status: decided
- Date: 2026-11-12
- Decided by: Robin (owner)
- Roadmap item: F-2.2, "Decide the durable scanner path" ([ROADMAP.md](../../ROADMAP.md), Step 2)

This record names the one scanner the durable-mode GitHub App service runs, its exact version and how it is installed, and lists the compatibility evidence a deployment must show before go-live. It records a decision. It installs nothing, builds nothing and authorizes no action: see "Not decided here / not authorized" below.

## Decision

Durable mode runs Semgrep 1.79.0, the version the project already pins and tests.

- **Scanner:** Semgrep. `PRSEC_SCANNER_COMMAND` keeps its default, `semgrep`.
- **Exact version:** 1.79.0, pinned as `semgrep==1.79.0` in [requirements.txt](../../requirements.txt) and [requirements-cli.txt](../../requirements-cli.txt). The command line and the GitHub Action install it, and CI runs `make check` with it on Python 3.11 to 3.14.
- **How it is installed:** with pip, from that pin unchanged: the `semgrep` package at exactly 1.79.0. No newer release, no version range and no dependency override.
- **Where it is installed:** in the scanner image. In durable mode the worker runs the scanner only in the Docker sandbox ([ARCHITECTURE.md](../../ARCHITECTURE.md), "Execution modes"), from an image that `PRSEC_SCANNER_IMAGE` names by digest and that is never pulled at scan time. The service's own environment, installed from [deploy/requirements-service.lock](../../deploy/requirements-service.lock), has no Semgrep.

[SECURITY.md](../../SECURITY.md) states where that pin stands: "`requirements.txt` and `requirements-cli.txt` pin Semgrep 1.79.0, and pip-audit reports no known vulnerabilities in either. The newest Semgrep tested, 1.182.1, pins MCP and OpenTelemetry releases with five known advisories, so it is not used."

No scanner image has been built. The decision says what the image must contain. It does not build or approve one.

## Compatibility evidence required before go-live

Before go-live the deployment must show all five results below for the Semgrep it runs. Each is tied to a command or file that already exists in the repository.

| # | Evidence | Existing command or file | What it must show |
|---|---|---|---|
| 1 | The exact pinned package and how it was installed | `requirements-cli.txt` and `requirements.txt`, line `semgrep==1.79.0` | The install command and the file it read. The installed package is `semgrep`, version exactly 1.79.0, from the pin unchanged. |
| 2 | The scanner's version output | `semgrep --version`, run in the scanner image that `PRSEC_SCANNER_IMAGE` names. `semgrep` is the entry point `docker_scan_command` in `analyzers/semgrep_runner.py` starts | Standard output is exactly `1.79.0`. |
| 3 | The planted-P1 self-check | `make selfcheck` (`Makefile`), a full scan of `tests/fixtures/project` | `selfcheck: OK, the planted P1 failed the gate (exit 1)` |
| 4 | The rule sample validation | `deploy/validate_scanner.py`. On the host, `deploy/accept_linux.py` runs it through the scanner image | `PASS: all 41 trusted rules; inline nosemgrep cannot suppress MD5 or eval; clean comparison passes.` |
| 5 | The 41 service-owned rules load | `make test`, which includes `tests/test_trusted_rules.py`. The rules are in `trusted_rules.py` | The suite passes: 41 rules (21 Python, 20 JavaScript and TypeScript), each matching its positive examples and none of its negative ones. |

Each result counts only together with the `semgrep --version` output of the executable that produced it. Evidence 2 and 4 come from the scanner image. Evidence 3 and 5 by default run Semgrep as a host subprocess: the executable `SEMGREP_BIN` names, or else the `semgrep` beside the Python that runs them, then the one on `PATH`.

CI already produces evidence 3, 4 and 5 on Semgrep 1.79.0 for every pull request: `make check` is `make test` then `make selfcheck`, and `tests/test_trusted_rules.py` runs the check in `deploy/validate_scanner.py` with the scanner as a host subprocess. That shows the pin and the rules agree. It is not evidence for a deployment, and none of the five has been shown for one: there is no host and no scanner image yet. A missing or failed result is not a pass, and go-live waits for it. The reviewable go-live checklist is a separate item (F-2.3).

## Option not chosen

Opengrep, evaluated at v1.33.0 in [deploy/mini-pc-scanner-evaluation.md](../../deploy/mini-pc-scanner-evaluation.md) as a way to avoid the two dependency families, MCP and OpenTelemetry, behind the five advisories found with Semgrep 1.182.1.

Why not: the repository's own evaluation leaves Opengrep unverified. Its release signature check never completed, its runnable binary was not audited ("Do not report the alternative as fully vulnerability-cleared yet"), and its recorded compatibility run covers 15 rules on a macOS build, while the rule file now holds 41.

The explicit Opengrep option in `analyzers/semgrep_runner.py` (`PRSEC_SCANNER_COMMAND=opengrep`) and `deploy/verify_opengrep_signature.py` stay in the repository, unchanged. A durable deployment does not select them: `deploy/check_environment.py --role worker` already fails when `PRSEC_SCANNER_COMMAND` is anything other than `semgrep`.

## Not decided here / not authorized

Each of these needs a separate owner approval before it happens. This record gives none of them.

- **Dependency or version changes:** adding, removing or changing a dependency line or a pinned version in any requirements file, including a move to another Semgrep release or another scanner.
- **Image build or audit:** building, obtaining, loading or auditing a scanner image, and choosing its base or its digest.
- **Deployment lock:** creating or changing `deploy/requirements-service.lock` or any other lock file, for the service or for the scanner.
- **Changes to `deploy/validate_scanner.py`:** anything beyond the sample that a new or changed service-owned rule requires.

Collecting the evidence above on a host or from an image is go-live verification work, and this record does not start it. The other Step 2 items (F-2.3 to F-2.5) are separate items. The approval gates and the required release verification in [deploy/README.md](../../deploy/README.md) still apply, including the image audit and the container tests in gate 3: until they pass, the service is not deployed.

## Existing statements that differ

The decision was compared with [ARCHITECTURE.md](../../ARCHITECTURE.md) and the documents in `deploy/` as they stood on 2026-11-12. This record changes none of them. Four points differ, and each is a follow-up item for later work.

### 1. The Semgrep version the deployment documents gate on

- `deploy/README.md`, "Approval gates", gate 3: "The tested Semgrep 1.182.1 has five unresolved advisories and is not approved".
- `deploy/README.md`, "Dependencies": "Semgrep 1.182.1's pins on `mcp` and `opentelemetry-api` block patched versions".
- `deploy/mini-pc-acceptance.md`, gate 1: "Obtain a supported Semgrep distribution permitting the patched dependencies".
- `deploy/scanner-security-review.md`, first line: "Status: unresolved; deployment gate remains closed."

All four are about Semgrep 1.182.1 and stay true of it. None names 1.79.0, the version the decision selects, so the scanner gate does not yet say what the chosen version must pass.

### 2. Opengrep as the preferred candidate

- `deploy/mini-pc-scanner-evaluation.md`, "Evaluated alternative: Opengrep v1.33.0": "Recommendation: retain Opengrep 1.33.0 as the preferred candidate". Under the decision Opengrep is not chosen.
- The same document's prerequisites list: "For explicit Opengrep selection set `PRSEC_SCANNER_COMMAND=opengrep`". A durable deployment does not set it.
- `deploy/deployment.env.example`: "opengrep is an evaluated alternative, not yet approved for deployment". The value it sets, `semgrep`, agrees with the decision.
- `deploy/verification-checkpoint.md`: "Run the existing signature script again when Rekor is reachable", repeated in `deploy/trust-boundaries.md`, "Signature verification checkpoint". Under the decision the Opengrep signature check is not a go-live step.
- `ARCHITECTURE.md`, "Components": the runner "runs Semgrep (or an explicitly selected Opengrep)", and `deploy/*.py` includes an "Opengrep signature check". Both still describe the code. Durable mode does not use either.

### 3. Recorded compatibility results are for other versions and 15 rules

- `deploy/mini-pc-scanner-evaluation.md`, "What was actually tested": "The actual Opengrep and Semgrep 1.182.1 executables both passed the 15-rule compatibility fixture in local subprocesses."
- `deploy/production-readiness.md`, "Verified components and blockers": "All 15 service-owned rules detect their fixtures", in a checkpoint whose test suite ran on "official Semgrep 1.182.1".
- `deploy/mini-pc-acceptance.md`, last paragraph: "all 15 production-rule compatibility checks passed". Gate 3 of the same document already says "all 41 rule results".

These were true when written. None is evidence for the chosen scanner: the version is now 1.79.0 and the rule file holds 41 rules.

### 4. How the scanner is installed

- `deploy/README.md`, "Install and run": the only install step reads `deploy/requirements-service.lock`, which has no Semgrep line. The section does not say how Semgrep gets into the scanner image, or which Semgrep the test run in the same block uses. Under the decision both are 1.79.0 from the existing pin.
- `deploy/README.md`, "Dependencies": "Semgrep and the service need separate environments (OpenTelemetry conflict)". The sentence is in the bullet about 1.182.1. For 1.79.0, `requirements.txt` installs Semgrep and FastAPI into one environment, and CI runs `make check` in it. In durable mode the scanner is in its own image either way.
- `deploy/README.md`, "Dependencies": "The developer `requirements.txt` has known advisories." `SECURITY.md` says pip-audit reports no known vulnerabilities in `requirements.txt` or `requirements-cli.txt`. The two disagree, and the decision takes its pin from those two files.

Other documents in `deploy/` repeat these points in their own words and are not listed one by one. Nothing else that was checked disagrees with the decision: `deploy/check_environment.py` and `deploy/accept_linux.py` accept or set only `PRSEC_SCANNER_COMMAND=semgrep`, `deploy/scanner-security-review.md` ends with "The user selected Semgrep; alternative-scanner evaluation is deferred.", and `ARCHITECTURE.md` requires the rootless Docker sandbox in durable mode and lists the scanner image as still open.
