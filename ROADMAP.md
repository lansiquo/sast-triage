# sast-triage: roadmap to an enterprise-grade SAST platform

Owner: Robin. Adopted 2026-11-11.

Owner-approved order of work for sast-triage. Items are built one at a time, lowest step first.
Status changes only through merged pull requests.

sast-triage is already a well-engineered diff-aware SAST gate for Python, JavaScript and TypeScript — a CLI, a GitHub Action and a GitHub App, with 41 service-owned rules, a fail-closed gate and 202 tests. v2.1.1 is released at `3ea9f876` (the 202-test count is from that released main snapshot); the signed package/image distribution below is still future work. This roadmap takes it from a strong single-tool, single-repo project to a multi-tool, multi-tenant platform, in seven phases, each opened by a gate that must pass before the next begins.

## Where it stands today

This is well past a toy. The core idea — diff-aware triage that labels each finding new or pre-existing by scanning the base version too, ranks it P1–P3, and fails the gate only on a new P1 — is a real differentiator, and the engineering around it is careful. The work to reach enterprise grade is about breadth, persistence, multi-tenancy and operations, not about fixing a shaky foundation.

Strengths to build on:

- Three delivery surfaces from one engine: CLI (scan_repo.py), GitHub Action (action.yml), and GitHub App webhook service (app.py).
- Serious security posture: mandatory HMAC webhook verification, installation tokens scoped to one repo and three permissions, a rootless-Docker sandbox design (--network=none, read-only, all caps dropped), fail-closed everywhere, 1 MiB limits, no repository archive fetched.
- 41 service-owned rules, including 8 taint-mode request-to-sink rules; one finding per file/line/CWE, most-severe kept.
- 202 tests against ~3.4k lines of source, a Python 3.11–3.14 CI matrix, SHA-pinned Actions, Keep-a-Changelog + SemVer, and solid ARCHITECTURE.md / SECURITY.md / CONTRIBUTING.md.

Gaps that matter for enterprise use:

| Dimension | Today | Enterprise bar |
|---|---|---|
| Deployment | Durable mode built but never run live; no host, no acceptance run | Running service, recovery proven on a real host |
| Scanner coverage | Semgrep only; Python/JS/TS only | Many scanners and languages via a common format |
| Persistence | Ephemeral — a Check Run + job summary per PR | Findings stored, tracked over time |
| Finding lifecycle | None | First-seen/fixed/reintroduced, suppression with audit, SLA |
| Tenancy & policy | One repo + one installation; gate hardcoded (new P1) | Many tenants, per-team policy-as-code |
| Access control | None (no UI/API) | SSO + RBAC |
| Surfaces | CLI, Action summaries and GitHub Checks | API, dashboard, SCM + ticketing integrations |
| Distribution | Clone-and-run; no package, no published image | Signed, versioned package + image + SBOM |
| Observability | "There are no alerts" | Metrics, traces, alerting, audit log |
| Scale | Single-host SQLite, one worker per queue | HA datastore, horizontal workers |

Each phase delivers something usable on its own and is opened by a gate; don't begin the next phase until the current gate passes.

## Delivery contract

The narrative below preserves Robin's enterprise direction. The numbered items are its reviewable delivery slices, each intended for one PR and at most one week including QA. No item is permission to change dependencies, deployment, workflows, hosting, settings, releases or trust boundaries. A `Needs owner:` line needs an explicit item-specific decision before implementation; a roadmap merge approves order, not those decisions. Owner-only files and operations need separate owner assignments even after a design decision.

The current step is the lowest numbered step containing a planned item. Step 1 is the deliberate exception before Phase 0: mostly owner work in Phase 0 must not prevent the five quick-win proposals from being considered first. Within a step, respect the item dependencies. Phase gates still apply: completing the currently sliced items does not satisfy a phase's "Done when" if deferred work or real-host evidence is missing, and does not authorize beginning the next phase. The coordinator must obtain the remaining owner work or an approved roadmap correction first.

Every item below has offline acceptance. Live hosting, publication, external identity providers and integrations, load evidence and external assurance are separate owner gates, never simulated into a claim of completion. Deferred work is retained explicitly under its phase and in the cross-cutting tracks; it needs future week-sized items before implementation. The public PR maps all original bullets, including these deferrals.

## Step 1: Quick wins (no owner decisions)

Goal: Users can export SARIF, diagnose missing base history and use the existing CLI controls and reports through the tokenless Action.

Phase 0 is mostly owner work, so these five items keep autonomous work moving. F-1.1 defines the normalized finding model reused by Phase 1; it serializes the existing triage result rather than creating a second ranking or gate engine.

### F-1.1 SARIF output from the command line (`--sarif FILE`)

- Status: planned
- Why: README "Use it on your project" lists only the console report, `--json` and `--markdown`, and README "GitHub Action" only writes the job summary, so findings can't reach GitHub code scanning or other SARIF tools. CHANGELOG 0.1.2 had a SARIF upload to the Security tab; the upload workflow was removed in commit `39da7e6`, before v1.0.0. This writer defines the normalized finding model (existing JSON finding fields plus their SARIF representation) reused by Phase 1 items F-3.1–F-3.4.
- Acceptance:
  - `scan_repo.py DIR --sarif FILE` writes a SARIF 2.1.0 JSON file (`"version": "2.1.0"`) with one run, `tool.driver.name` `sast-triage`, each reported rule ID once in `tool.driver.rules`, and one result per finding in the `--json` output for the same input, in the same order.
  - Each result carries `ruleId`, the relative path with forward slashes as `locations[0].physicalLocation.artifactLocation.uri`, `region.startLine` and `region.endLine`, the finding's `fingerprint` under `partialFingerprints`, and `properties` with `priority`, `new`, `new_because` and `cwe` equal to the finding's `--json` fields.
  - Each result's `level` follows the Check Run annotation levels: `error` for a new P1, `warning` for a new P2, `note` otherwise.
  - With `--base REF`, `properties.new` is false for a pre-existing finding and true for a new one, matching `--json` for the same run.
  - With nothing to scan, the command exits 0 and FILE holds one run with no results.
  - On a scanner error, a git error or a file over 1 MiB, the command exits 2, FILE is not created, and an existing FILE is left unchanged.
  - Adding `--sarif` does not change the exit status, the console report, the `--json` output or the `--markdown` file for the same input.
  - An unwritable output destination or invalid option exits 2 without a partial success artifact; tests cover full scans and --base scans.
- Out of scope: uploading SARIF; an Action input (F-1.5); new fields in `--json`.
- Touches: scan_repo.py, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: M

### F-1.2 Actionable errors when the `--base` history is missing

- Status: planned
- Why: README "GitHub Action" and `action.yml` say a `--base` scan needs the base branch's history (`fetch-depth: 0`). Without it the ref is missing, and `changes_since` in `scan_repo.py` checks it with `git rev-parse --verify --quiet`, so the only message is "cannot diff against origin/main, no result issued." followed by "git rev-parse failed". A shallow history without the merge base ends with git's own "no merge base" text and no hint either.
- Acceptance:
  - In a repository without the ref, `scan_repo.py DIR --base origin/missing` exits 2, issues no result, and stderr names the ref, says it is not a commit in this checkout, and mentions `git fetch` and `fetch-depth: 0`.
  - In a shallow clone (`git clone --depth 1`) where the base ref exists but its merge base with `HEAD` is not in the history, the command exits 2, issues no result, and stderr says no merge base was found and mentions `fetch-depth: 0`.
  - A `--base` value that starts with `-` is still refused with exit status 2 before git is run with it.
  - The exit status and output of a successful `--base` scan are unchanged.
- Out of scope: fetching history automatically (a scan makes no network calls); changing the Action's checkout instructions.
- Touches: scan_repo.py, tests/test_scan_repo.py, README.md ("Exit codes", if the wording changes), CHANGELOG.md
- Size: S

### F-1.3 Action input for the scan time limit

- Status: planned
- Why: `scan_repo.py --timeout` (default 300 seconds, README "Use it on your project") is the only way to give a large scan more time, but `action.yml` has only the `path` and `base` inputs, so an Action user whose scan needs more than 300 seconds gets exit status 2 and can't raise the limit.
- Acceptance:
  - `action.yml` declares an optional `timeout` input with default `""`.
  - With `timeout` empty, the Scan step runs `scan_repo.py` with the same arguments as today (no `--timeout`); with `timeout: 600` it adds `--timeout 600`. A test runs the Scan step's script from `action.yml` with a stub in place of the interpreter and checks the arguments in both cases.
  - The input reaches the script only through an environment variable, as `path` and `base` do: `${{ inputs.timeout }}` does not appear inside a `run` script.
  - A value that is not a whole number makes the step exit 2 with no result, as `scan_repo.py --timeout abc` does.
  - README "GitHub Action" documents the input and its default.
  - Tests repeat empty, valid and invalid timeout cases with a base ref and with base: none; the base arguments and gate result are otherwise unchanged.
- Out of scope: the GitHub App's scan timeout; changing which values `--timeout` accepts; the Action's install step and permissions.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

### F-1.4 Pull request annotations from the command line and the Action

- Status: planned
- Why: The GitHub App reports findings as Check Run annotations, up to 200 and P1 first (README "Review pull requests with a GitHub App"), but the Action only adds the Markdown summary to the job summary (README "GitHub Action"). That summary names at most 10 new P1 findings and none of the P2, P3 or pre-existing ones (`summarize_findings` in `analyzers/semgrep_runner.py`), so Action users can't see where those are without reading the log.
- Acceptance:
  - `scan_repo.py DIR --github-annotations` prints, after the report, one GitHub workflow command per finding with `file`, `line`, `endLine` and `title` properties: `::error` for a new P1, `::warning` for a new P2 and `::notice` otherwise, the same levels as the App's annotations.
  - At most 200 commands are printed, in the App's annotation order (P1 first).
  - Text is escaped as GitHub requires (`%`, carriage return and line feed in the message; also `:` and `,` in properties): a test with a finding whose path holds a comma, a colon, a percent sign and a line feed gets exactly one command line for it, with the escaped path.
  - `--github-annotations` together with `--json` exits 2 with a usage error.
  - On a scanner or git error the command exits 2 and prints no workflow command.
  - Without the flag, the output is unchanged.
  - `action.yml` has an optional `annotations` input, default `"false"`; `"true"` adds the flag; any other value makes the step exit 2 before scanning. The input reaches the script only through an environment variable.
  - A --base fixture with one new and one pre-existing finding yields the corresponding levels without changing the gate. Hostile finding text cannot create an extra workflow command.
- Out of scope: creating Check Runs from the Action (it uses no token); changing the App's annotations.
- Touches: scan_repo.py, analyzers/semgrep_runner.py (sharing the annotation levels only), action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: M

### F-1.5 Action input that writes SARIF

- Status: planned
- Why: After F-1.1 the command line writes SARIF, but the Action can't ask for it. SECURITY.md says the Action uses no token and README "GitHub Action" says it uses no other actions, so a user's own workflow step has to do the upload.
- Acceptance:
  - `action.yml` has an optional `sarif` input, default `""`; when set, the Scan step passes `--sarif` with that path; when empty, the arguments are unchanged. The input reaches the script only through an environment variable.
  - When the scan exits 2, no new file is created at that path and any existing file stays unchanged. The documented separate upload step checks for a completed exit-0/exit-1 scan so it never uploads a stale file after exit 2.
  - README "GitHub Action" shows a separate upload step in the user's workflow, pinned to a full commit SHA, notes that the step needs `security-events: write`, and states that sast-triage itself still uses no token and no other actions.
  - Tests cover full scans and --base scans, paths with spaces, and invalid or unwritable output paths (exit 2 with no partial artifact). Upload remains a user-workflow concern.
- Out of scope: uploading from the Action (F-6.1); any permission of the Action.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

## Step 2: Go live, and ship a real release

### Phase 0 — Go live, and ship a real release

Goal: turn the durable mode you've already designed into a running, verified service, and make the project installable and distributable. This is the single biggest credibility jump available, and most of it is finishing work you've already specified in deploy/.

- Provision the host from your deploy plan: a dedicated Linux VM, separate web and worker OS users, the queue-group file permissions, and a rootless Docker daemon only the worker can reach.
- Finalize and audit the scanner image: pin it as name@sha256:..., run with --pull=never, and resolve the Semgrep version bind first (the 1.79.0 pin vs. the advisories on newer releases) — either clear the mcp/opentelemetry conflict or adopt the Opengrep path you've already evaluated.
- Run the deploy/README.md "required release verification" on the real host: unsigned/invalid payloads create nothing; a signed payload is queued exactly once across redelivery and restart; a worker restart mid-scan recovers against GitHub; a vulnerable fixture PR fails on its exact commit and a clean one then passes; no Check ever targets another repo.
- Ship distribution: add pyproject.toml, publish a pip-installable package and pinned CLI, and publish a signed container image with an SBOM attached to each release.
- Wire minimal operations: monitor /ready, alert on job_terminal_failure, and document the restart/recovery runbook.

Done when: a real pull request is scanned end-to-end in durable mode on the host, worker recovery is proven against GitHub, and a tagged release ships a signed image + SBOM.

Delivery mapping: F-2.1 and F-2.2 settle hosting/scanner choices; F-2.3 prepares host, recovery and monitoring evidence; F-2.4 prepares local distribution; F-2.5 settles the product direction before Step 3. Actual provisioning, image auditing, live GitHub verification, publishing a signed package/image with SBOM and installing alerts are deferred owner operations. Their plans do not satisfy this phase's Done when. The existing v2.1.1 release is not evidence of those future distribution or deployment milestones.

### F-2.1 Decide hosting and trust

- Status: planned
- Needs owner: Choose a self-hosted lab service on the dedicated Linux VM or a hosted multi-tenant service. Separately approve the host, network exposure and placement of the App key and webhook secret before any provisioning or cutover.
- Why: deploy/README.md "Approval gates" leaves the host, credentials and cutover unapproved; ARCHITECTURE.md limits a deployment to one repository and installation.
- Acceptance:
  - A decision document records exactly one hosting option, the intended operator and tenant scope, and separate yes/no decisions for host provisioning, network exposure and credential placement; unresolved choices remain explicitly blocked.
  - A gate checklist links each Phase 0 hosting task to that decision and states that no host, tunnel, secret transfer or webhook change is authorized by merging the roadmap.
  - Offline documentation review finds F-2.3, F-5.2–F-5.5 and Steps 7–8 blocked on this decision wherever their scope depends on hosting.
- Out of scope: Provisioning, credentials, spending, deployment settings or any live service change.
- Touches: docs/hosting-decision.md, ARCHITECTURE.md (approved scope only)
- Size: S

### F-2.2 Decide the durable scanner path

- Status: planned
- Needs owner: Choose the tested Semgrep 1.79.0 pin or the evaluated Opengrep path for durable mode. Any dependency/version change, image audit, deployment lock or non-sample change to deploy/validate_scanner.py requires a separate owner assignment.
- Why: requirements.txt and requirements-cli.txt pin Semgrep 1.79.0; deploy/README.md requires an audited immutable image before durable deployment.
- Acceptance:
  - A decision record names one scanner, exact version and compatibility evidence required for all 41 service-owned rules, safe examples and the planted-P1 selfcheck.
  - The record states that durable go-live remains blocked until the selected image has an owner-reviewed digest and evidence for no egress, non-root execution, read-only mounts and existing resource limits.
  - A checklist distinguishes a new or changed rule sample in deploy/validate_scanner.py from scanner compatibility or harness changes: only the rule sample exception is ordinary feature work; every other change needs owner authorization.
- Out of scope: Changing dependencies, deployment files, images or the scanner in this decision PR.
- Touches: docs/scanner-decision.md
- Size: S

### F-2.3 Make the go-live evidence checklist reviewable

- Status: planned
- Needs owner: After F-2.1 and F-2.2, approve the durable-mode verification plan and name an operator for host setup, live GitHub verification and minimal monitoring. These are owner-run operations, not authorized Feature Bot actions.
- Why: deploy/README.md "Required release verification" says none of the actual-host checks has run; its "Operations" section says there are no alerts.
- Acceptance:
  - A documentation-only checklist maps every required release verification to an expected result and an evidence field: invalid or unsigned payloads create no job; signed redelivery and restart retain one queued job; restart during scanning and between Check creation and persistence recovers; vulnerable then clean fixture commits fail then pass on their exact repository and SHA.
  - The checklist includes separate web/worker users, queue directory 2770/database 660, worker-only rootless Docker access, immutable image digest and --pull=never. Offline review can check every row without claiming a live run occurred.
  - The operator runbook names /ready 503 and job_terminal_failure as alert inputs, includes synthetic healthy/degraded log and response examples with expected alarm state, and gives restart/recovery and evidence-redaction steps.
  - The document has a NOT_RUN field for each live check and states that a complete checklist alone cannot satisfy Phase 0 Done when or authorize the next phase.
- Out of scope: Provisioning, modifying deploy/, live webhook or PR activity, installing monitoring, or claiming production readiness.
- Touches: docs/go-live-checklist.md, docs/operator-runbook.md
- Size: M

### F-2.4 Prepare a locally installable CLI package

- Status: planned
- Needs owner: Approve adding pyproject.toml and package metadata/entry points, the package name and the build backend. Any new build dependency, version field or release automation needs owner work; publishing and signing remain separate decisions.
- Why: README "Use it on your project" requires a clone and virtualenv; the repository has no pyproject.toml or pip-installed CLI.
- Acceptance:
  - With the approved build tools preinstalled, an offline test builds a wheel and installs it with --no-deps into a temporary environment; the documented installed entry point prints help and scans tests/fixtures/project with exit 1, matching scan_repo.py.
  - The wheel includes the service-owned rules and required analyzer modules; it excludes .env files, keys, scanned fixtures and deployment credentials.
  - An invalid directory produces exit 2 and no success result through the installed command. Existing clone-and-run commands still pass make check.
  - README documents local installation and clearly says no PyPI package, signed image or SBOM has been published by this item.
- Out of scope: PyPI publication, tags, version edits by Feature Bot, container builds, signing, SBOM publication and workflows.
- Touches: pyproject.toml and packaging/entry-point files (owner-authorized), tests/, README.md, CONTRIBUTING.md, CHANGELOG.md
- Size: M

### F-2.5 Decide the product framing before Phase 1

- Status: planned
- Needs owner: Choose "Semgrep reviewer" or "triage/gate layer over any scanner". The latter needs explicit approval for imported scanner output, new languages and separate future secrets/SCA adapters; approving this decision does not approve every adapter.
- Why: README calls the product a Semgrep reviewer; ARCHITECTURE.md "Out of scope" excludes other languages, secrets detection and dependency analysis.
- Acceptance:
  - A decision document records one choice and an explicit in/out scope list for native Semgrep, imported SAST, new languages, secrets and SCA/container output.
  - If Semgrep reviewer is selected, every Phase 1 expansion and dependent enterprise item is marked blocked pending a separate roadmap correction; it is not silently treated as done or built anyway.
  - If the triage/gate layer is selected, the document records F-1.1 as the normalized finding contract and requires separate owner approval for F-3.1–F-3.4; Native rule coverage remains unscheduled until Robin chooses its priority.
- Out of scope: Implementing ingestion, changing rules, new scanners or changes to the companion repository.
- Touches: docs/product-decision.md, README.md and ARCHITECTURE.md (approved future scope only)
- Size: S

## Step 3: Become a triage platform (SARIF ingestion)

### Phase 1 — Become a triage platform (SARIF ingestion)

Goal: decouple your triage-and-gate engine from Semgrep. Ingest SARIF 2.1.0 from any scanner, normalize it, and run the same new/pre-existing, P1–P3 and gate logic over it. This is the highest-leverage architectural move in the whole roadmap: it multiplies language and tool coverage with no new rules to maintain, and it reframes the product from "a Semgrep reviewer" to "a triage and gate layer over any SAST/SCA output."

- Build a SARIF ingestion layer: parse results, map ruleId, level/severity and locations, and dedupe across tools by file/line/CWE keeping the most severe — the same rule you already apply within Semgrep.
- Normalize severity across tools into your P1–P3 model via a documented mapping config, so a CodeQL error and a Semgrep ERROR land consistently.
- Preserve the diff-aware labeling on SARIF: use SARIF partialFingerprints (plus your own line-text fingerprint) to carry new/pre-existing across tools.
- Add presets for common scanners that already emit SARIF: CodeQL, Bandit, ESLint-security, secrets scanners (Gitleaks/TruffleHog), and SCA/container scanners (Trivy/Grype) alongside your native Semgrep path.
- Gain languages as a side effect: Java, Go, C#, Ruby and more, via whichever scanner produced the SARIF.
- Offer a "bring your own scanner output" mode: teams run scanners in their own CI and pipe SARIF to sast-triage for triage + gate.

Done when: two different scanners' SARIF (e.g. Semgrep + CodeQL) are triaged through one gate with new/pre-existing labels intact.
Decision to settle before building: this commits the product's identity. It's the right move for "enter enterprise grade," but your native rules become one input among many rather than the whole product. Decide it deliberately (see Where to start).

Delivery mapping: F-3.1–F-3.4 depend on F-1.1 and F-2.5 and cover parsing/deduplication, severity, matching and a two-scanner bring-your-own-output path. F-3.5 settles the datastore before Step 4. Bandit, ESLint-security, Gitleaks/TruffleHog and Trivy/Grype presets, plus additional languages beyond the explicit first CodeQL fixture, are deferred until separate adapter contracts and scope approvals exist. Importing SCA output here does not authorize any change to sca-triage.

### F-3.1 Parse SARIF into the shared finding model

- Status: planned
- Needs owner: After F-2.5, approve importing externally produced SARIF 2.1.0 and its trust boundary. This does not approve running another scanner or accepting arbitrary languages without the selected scope.
- Why: README exposes console, JSON and Markdown output only. F-1.1 defines the normalized finding model that this parser reuses instead of inventing another priority or gate model.
- Acceptance:
  - Offline parser tests load synthetic Semgrep and CodeQL SARIF 2.1.0 fixtures into F-1.1 fields, preserving tool identity, ruleId, CWE, relative path, start/end lines and source severity. No input file is executed or imported.
  - Within and across runs, findings at the same file/line/CWE keep the most severe finding and retain source-tool provenance; distinct CWEs remain distinct. Permuting tool order yields the same normalized result.
  - Malformed JSON, wrong SARIF version, unknown severity, missing required locations, absolute/traversing/backslash paths and external URI references produce an explicit import error and no findings result. A valid empty run produces an empty result.
  - The parser documents fixed input-byte and result-count bounds selected in the owner-approved contract; boundary tests accept the limit and reject limit plus one without changing native scan limits.
- Out of scope: CLI wiring, scanner execution, network retrieval, new dependencies, secrets/SCA presets or changed gate semantics.
- Touches: analyzers/ SARIF parser, tests/ and synthetic fixtures, docs/sarif.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-3.2 Define explicit severity mappings for imported results

- Status: planned
- Needs owner: Approve the per-tool mapping and its configuration authority because it changes how external severities become P1–P3. Choose service-owned mapping only or an explicitly supplied operator mapping; scanned-repository configuration must never decide it.
- Why: README "How triage works" defines one native severity model; SARIF levels alone cannot reliably express another scanner’s security severity. Depends on F-1.1, F-2.5 and F-3.1.
- Acceptance:
  - A documented mapping fixture lists each supported Semgrep and CodeQL severity, including its native metadata field, and expected P1/P2/P3 in runtime and test code. Offline table tests assert every row.
  - Equivalent high-severity Semgrep and CodeQL fixtures rank identically; native Semgrep fixtures retain their previous priorities and exit codes.
  - Missing, unknown or conflicting severity values and malformed mappings fail import with no result rather than defaulting to a lower priority. Tests prove an in-repository mapping file is ignored.
- Out of scope: Changing P1’s native definition, gate thresholds, remote config, secrets/SCA mappings or implicit fallback for unknown tools.
- Touches: analyzers/ normalization, tests/, docs/sarif.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-3.3 Carry diff-aware labels through imported findings

- Status: planned
- Needs owner: Approve the imported head/base provenance and fingerprint contract before changing matching behavior. A foreign partialFingerprint alone must never establish that a finding is pre-existing.
- Why: README "Scope and limits" matches findings by rule and covered-line text; imported results need the same evidence. Depends on F-1.1, F-2.5, F-3.1 and F-3.2.
- Acceptance:
  - Offline paired head/base SARIF and source fixtures preserve new/pre-existing labels under a line-number shift when rule identity and covered-line text still match; source-tool provenance and partialFingerprints are retained.
  - A finding on changed lines or absent from the base remains new even when a supplied partialFingerprint matches. An unrelated rule with the same fingerprint cannot make it pre-existing.
  - Missing or unscannable base content makes that file’s findings new; failed merge-base lookup or malformed imported scan fails with no result. Rename from test to runtime remains new.
  - Native Semgrep JSON, Markdown, gate results and existing matching tests are unchanged. The documented imported mode states how tool identity participates in matching and when cross-tool evidence is insufficient.
- Out of scope: Cross-file/function flow, inferring equivalence between unrelated rules, persistent baselines or trusting scanner-provided suppression.
- Touches: analyzers/triage.py and SARIF normalization, tests/, docs/sarif.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-3.4 Triage supplied Semgrep and CodeQL reports from the CLI

- Status: planned
- Needs owner: Approve a distinct import CLI interface and its explicit supported-language scope, following F-2.5. It reads reports and source evidence only; it never invokes or installs CodeQL or another scanner.
- Why: README currently requires running the native scanner. A bring-your-own-output command makes F-1.1 and F-3.1–F-3.3 usable without adding scanner runtimes.
- Acceptance:
  - A documented offline command takes synthetic Semgrep and CodeQL reports for the same revision, plus explicit source/base evidence, and emits one normalized JSON/SARIF report and one gate result: exit 1 for new P1, 0 for a complete report without new P1, 2 for invalid or incomplete input.
  - Contract fixtures for both presets assert priorities, duplicate handling, provenance, new/pre-existing labels and output fields. At least one CodeQL fixture uses an explicitly approved language beyond Python/JS/TS.
  - Empty valid reports pass; malformed reports, incomplete-scanner markers, mismatched revision provenance and unknown presets exit 2 with no output artifact. A test proves the command makes no network call or scanner subprocess call.
  - The guide shows teams generating reports in their own CI, explains that report completeness is an explicit trust requirement, and documents the native scan command unchanged.
- Out of scope: App/Action ingestion, executing third-party scanners, Bandit/ESLint/security-secrets/SCA presets and additional languages without their own contract fixtures.
- Touches: scan_repo.py or an owner-approved import CLI, analyzers/, tests/, README.md, docs/sarif.md, CHANGELOG.md
- Size: M

### F-3.5 Decide the finding datastore path before Phase 2

- Status: planned
- Needs owner: Choose SQLite-only self-hosting or SQLite plus a Postgres tier. Approve the stable finding identity and migration contract before storing runs or findings; a database driver or dependency remains a separate owner change.
- Why: job_store.py stores queue state, not a finding history; ARCHITECTURE.md documents a single-host SQLite queue. The schema reuses the F-1.1 normalized finding contract, and Phase 2/3/5 schemas depend on this decision.
- Acceptance:
  - A decision record names exactly one datastore path and defines run identity, stable finding identity, repository/installation scope, schema versioning and backup/restore ownership.
  - The document includes a schema fixture and a transition matrix for first-seen, last-seen, fixed, reintroduced and accepted-risk states, with commit/PR provenance and UTC timestamps.
  - F-4.1–F-4.5, tenant isolation and F-7.1 are explicitly blocked until this decision is approved. SQLite-only selection leaves a Postgres implementation deferred rather than silently authorized.
- Out of scope: Database migration, production writes, new drivers, changing the queue, or implementing lifecycle behavior.
- Touches: docs/datastore-decision.md, ARCHITECTURE.md
- Size: S

## Step 4: Persistence and finding lifecycle

### Phase 2 — Persistence and finding lifecycle

Goal: store findings and runs so the tool tracks security posture over time, not just gate one pull request. Every later enterprise feature — dashboards, SLAs, suppression review, per-team policy — depends on this layer, so it comes before them.

- Add a datastore for runs and findings keyed by a stable fingerprint, each carrying first-seen, last-seen, status, and commit/PR provenance.
- Model finding states and transitions: open → fixed (detected automatically when a finding disappears), reintroduced, and won't-fix / accepted-risk.
- Build a suppression workflow with an audit trail — who suppressed what, why, when, and when it expires. Keep your existing trust boundary: suppression is a service-side decision, not an in-repo nosemgrep comment a PR author controls.
- Generalize your "full scan vs. --base" idea into persistent baselines per branch: adopt an existing codebase's findings as a baseline so only new ones gate.
- Track aging and SLA: time-to-remediate per severity, with overdue flags.

Done when: a finding's lifecycle persists across runs (first-seen, fixed, reintroduced) with an auditable suppression trail.

Delivery mapping: the five items cover run/finding storage, lifecycle, audited accepted risk, branch baselines and SLA calculations. They depend on the approved F-3.5 datastore path. API/UI review flows and real database migrations remain separate work.

### F-4.1 Persist completed runs and stable finding records

- Status: planned
- Needs owner: After F-3.5, approve durable storage of findings and source-derived metadata, its retention and access boundary, and the new storage module. Use temporary databases in tests only.
- Why: ARCHITECTURE.md describes a durable job queue but no finding store; README reports only a per-run result.
- Acceptance:
  - Offline tests write two complete synthetic runs to a temporary SQLite store and reopen it; records retain stable fingerprint, first-seen, last-seen, repository, commit/PR provenance and run identity.
  - Replaying a completed run does not duplicate findings or reset first-seen. A transaction interrupted before commit exposes neither a partial successful run nor partial findings.
  - Failed, cancelled or incomplete scans cannot be stored as complete clean runs; fixture assertions show no fixed findings inferred from them. Stored records and logs contain no tokens or webhook bodies.
- Out of scope: Production database writes, queue migrations, Postgres, API/UI access or lifecycle transitions beyond initial open state.
- Touches: owner-approved finding-store module, tests/, ARCHITECTURE.md, docs/datastore.md, CHANGELOG.md
- Size: M

### F-4.2 Track fixed and reintroduced findings

- Status: planned
- Needs owner: Approve lifecycle semantics over the F-4.1 store, including how complete scan coverage establishes absence. Depends on F-3.5.
- Why: README reports new/pre-existing for a single diff; no first-seen/fixed/reintroduced history survives the run.
- Acceptance:
  - Offline run sequences open → absent → present produce open, fixed and reintroduced states with preserved original first-seen, updated last-seen and commit/PR transition provenance after reopening the database.
  - Only a complete run covering the same scope can mark an absent finding fixed; partial, failed and changed-files-only runs cannot fix findings outside their coverage.
  - Duplicate runs and out-of-order replay do not duplicate transitions or move timestamps backward. The documented transition matrix matches tests for every permitted and rejected transition.
- Out of scope: Suppression, baselines, notifications and scanner or gate changes.
- Touches: finding store and lifecycle logic, tests/, docs/datastore.md, CHANGELOG.md
- Size: M

### F-4.3 Record expiring accepted-risk decisions

- Status: planned
- Needs owner: Approve service-side suppression authority, the meanings of accepted-risk and won’t-fix, expiry requirements and their effect on the gate. No scanned-repository comment or config may authorize suppression.
- Why: SECURITY.md ignores nosemgrep and warns that findings contain source-derived text; audited service-side decisions are needed before suppressions can affect results. Depends on F-4.1–F-4.2.
- Acceptance:
  - Offline store tests record actor, finding identity, reason, creation time, expiry and accepted-risk/won’t-fix decision; append-only history survives reopen and includes revocation.
  - Missing actor/reason, invalid expiry or an unauthorized caller is rejected with no state change. A fake clock proves expiry restores the approved unsuppressed behavior.
  - Fixtures containing nosemgrep or an in-repository suppression file cannot create an accepted-risk record. A failed audit write rolls back the decision.
  - Documentation states the approved gate behavior explicitly and tests both suppressed and unsuppressed results against it.
- Out of scope: UI review queue, external authentication, secrets in audit records or permission changes.
- Touches: finding-store decision service, tests/, ARCHITECTURE.md, docs/suppressions.md, CHANGELOG.md
- Size: M

### F-4.4 Adopt an explicit branch baseline

- Status: planned
- Needs owner: Approve who may adopt a baseline and how baseline adoption affects gate semantics. A pull request author must not be able to promote their own findings into a trusted baseline.
- Why: README "Use it on your project" counts every full-scan finding as new; an existing codebase cannot retain an explicitly adopted baseline. Depends on F-3.5 and F-4.1–F-4.2.
- Acceptance:
  - Offline tests adopt a complete stored run for one repository and branch; its unchanged findings are baseline findings, while an additional finding in the next run is new and follows the existing threshold.
  - Adoption records actor, run, branch, commit and timestamp. Incomplete runs, another repository’s run and unauthorized adoption are rejected without mutation.
  - Baselines for two branches remain independent; reopening the temporary store retains both. Existing --base matching remains unchanged when no persistent baseline is selected.
- Out of scope: Automatic adoption, silently replacing git merge-base evidence, cross-repository baselines and changing the default gate.
- Touches: finding store and baseline service, tests/, docs/baselines.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-4.5 Compute finding age and overdue status

- Status: planned
- Needs owner: Approve per-severity remediation targets and whether accepted-risk periods pause the SLA clock. SLA reporting must not change the gate unless separately approved.
- Why: README’s one-run summary has no aging or time-to-remediate view. F-4.1–F-4.3 provide the timestamps and decisions this calculation needs.
- Acceptance:
  - A documented target table gives a duration for each severity and the accepted-risk clock rule; fake-clock tests cover just before, exactly at and just after each deadline.
  - Stored open, fixed and reintroduced fixture findings produce age, remediation duration and overdue fields according to that table, with UTC timestamps and no negative durations.
  - Missing or invalid targets produce an explicit configuration error instead of a misleading on-time result. The same fixtures retain their previous gate result.
- Out of scope: Notifications, dashboards, contractual SLOs and automatic risk acceptance.
- Touches: finding lifecycle reporting, tests/, docs/sla.md, CHANGELOG.md
- Size: S

## Step 5: Multi-tenancy, policy-as-code and access control

### Phase 3 — Multi-tenancy, policy-as-code and access control

Goal: lift the one-repo, one-installation limit and make gate policy and access configurable per team. This is what turns a single-repo tool into something an organization can deploy.

- Support org-wide GitHub App installation across many repositories, and many installations per deployment, with per-installation isolation.
- Introduce policy-as-code: per-repo/per-team config for which severities block (your gate is hardcoded to "new P1" today), centrally governed path/rule exclusions, and who may accept risk. Fail closed when policy is missing.
- Define a tenancy model and enforce data isolation in the datastore.
- Add AuthN/AuthZ for any API or UI: SSO via OIDC/SAML and RBAC (viewer / triager / admin), scoped per tenant.

Done when: two tenants run fully isolated, each with its own gate policy enforced, and access is controlled by role.

Delivery mapping: the first item preserves the previous opt-in P2 proposal. F-5.2–F-5.5 cover isolation, App routing, central policy and the role boundary. A real OIDC or SAML adapter, the second SSO protocol, tenant provisioning and live org-wide installation are deferred owner-approved slices; the role contract alone does not satisfy this phase's access-control gate.

### F-5.1 Opt-in gate on new P2 findings

- Status: planned
- Needs owner: Should a stricter gate exist? Choose one: (a) no, the gate stays "new P1 only" everywhere; (b) yes, for the command line and the Action only (`--fail-on P2` and a `fail-on` input), documented as a deliberate difference from the App; (c) yes, for the App too, through a service setting. The acceptance below is for option (b); option (c) requires an approved App-specific slice and parity tests before implementation. Option (a) drops this item through a roadmap PR. This is the first item in the policy-as-code phase.
- Why: README "How triage works" fixes the gate at new P1 findings, and a new P2 (medium severity in runtime code, such as `js-open-redirect` or `js-cookie-without-secure`) is only a warning. A team that wants those to block a merge has no option. This changes gate semantics and the meaning of exit status 1, so it needs Robin.
- Acceptance:
  - `scan_repo.py DIR --fail-on P2` exits 1 when a new P1 or a new P2 finding is reported and 0 otherwise; pre-existing findings and P3 findings never fail it.
  - Without `--fail-on`, or with `--fail-on P1`, the exit status and output are unchanged.
  - `--fail-on` with any other value exits 2 with a usage error.
  - With `--base`, a pre-existing P2 does not fail the gate.
  - The Markdown summary states the threshold, and `--json` adds a `fail_on` field; no existing field is renamed or removed.
  - The Action's `fail-on` input, default `""`, reaches the script only through an environment variable.
  - README "How triage works", "Exit codes" and "GitHub Action" document the threshold and say that the App still gates on new P1 findings only.
- Out of scope: failing on P3 or on pre-existing findings; changing what counts as P1 or P2.
- Touches: scan_repo.py, analyzers/triage.py, action.yml, tests/test_scan_repo.py, tests/test_triage.py, README.md, CHANGELOG.md; with option c also app.py and ARCHITECTURE.md
- Size: M

### F-5.2 Enforce tenant isolation in stored findings

- Status: planned
- Needs owner: After F-2.1, F-2.5 and F-3.5, approve the tenant-to-installation/repository model and migration of stored records. Existing single-repository scope must not be widened implicitly.
- Why: ARCHITECTURE.md "Security controls" permits one repository and installation per deployment. Persistent data needs an explicit isolation boundary before multi-tenant access.
- Acceptance:
  - Offline tests create two tenants with overlapping rule IDs and fingerprints; reads, writes, baseline adoption and suppression by tenant A cannot see or mutate tenant B’s data.
  - Every storage access requires an authenticated tenant context; absent, unknown or mismatched context is denied rather than selecting a default tenant.
  - A temporary-database migration assigns existing single-repository data to one explicit tenant and refuses ambiguous ownership. Rollback/restart tests preserve ownership and record counts.
- Out of scope: Real database migration, App permission changes, tenant provisioning UI and cross-tenant aggregation.
- Touches: finding store, tests/, ARCHITECTURE.md, docs/tenancy.md, CHANGELOG.md
- Size: M

### F-5.3 Route App jobs by approved installation and repository

- Status: planned
- Needs owner: Approve multi-repository/multi-installation App scope and webhook changes after F-2.1 and F-5.2. Choose the allowed registration source; no job may expand its own scope or token permissions.
- Why: ARCHITECTURE.md constrains jobs and tokens to one repository and installation. Supporting two installations must retain that narrowing per job.
- Acceptance:
  - Offline integration tests deliver signed events for two registered installations and repositories; each job is assigned to the right tenant, and every requested token is narrowed to that job’s one repository and the existing three permissions.
  - Unknown installation/repository pairs, cross-tenant payload mismatches and invalid signatures enqueue nothing; workers reject a mismatched stored context before any mocked GitHub call.
  - Redelivery, restart and superseded-context tests retain dedupe/cancellation behavior for each tenant without sharing results or cooldown state incorrectly. The approved shared-versus-per-tenant cooldown choice is documented and tested.
- Out of scope: Installing the App, changing GitHub settings or permissions, real webhooks and additional SCM providers.
- Touches: app.py, worker.py, job_payload.py, job_store.py, tests/, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-5.4 Load centrally governed team gate policy

- Status: planned
- Needs owner: Approve the policy source, precedence, permitted exclusions and risk-acceptance roles. This changes gate and trust semantics; scanned-repository policy cannot be trusted just because it is checked in.
- Why: README "How triage works" hardcodes new-P1 gating; F-5.1 supplies the threshold mechanism and F-5.2 supplies tenant context.
- Acceptance:
  - Offline fixtures for two tenants choose distinct approved thresholds and produce the corresponding gate results for the same normalized findings; omitted or invalid policy fails closed with no successful gate.
  - The documented schema covers repo/team precedence, centrally authorized path/rule exclusions and allowed risk-acceptance roles. Tests reject unknown fields, invalid paths and policy belonging to another tenant.
  - A repository-authored policy or nosemgrep comment cannot override the trusted policy; each evaluated run records the policy revision and exclusion reason without removing the underlying finding record.
- Out of scope: Policy editing UI, remote policy fetching, new severity definitions and unapproved automatic exclusions.
- Touches: triage policy module, finding-store provenance, tests/, ARCHITECTURE.md, docs/policy.md, CHANGELOG.md
- Size: M

### F-5.5 Define and enforce the tenant role boundary

- Status: planned
- Needs owner: Approve viewer/triager/admin capabilities and the authenticated-principal contract for future API/UI access. Choose OIDC first or SAML first for a separately scoped SSO integration; new auth dependencies need owner approval.
- Why: There is no finding API/UI in README, and ARCHITECTURE.md exposes only webhook and health routes. Role checks must precede new surfaces.
- Acceptance:
  - An offline capability matrix tests viewer read-only access, triager risk-decision access and admin policy access, each scoped to a tenant; every denied operation leaves stored state unchanged.
  - Missing identity, expired identity evidence, unknown roles and a tenant mismatch are denied. Tests use a synthetic verified-principal fixture, never treating raw request headers as authenticated identity.
  - Documentation names the selected first SSO protocol and says that API/UI deployment remains blocked until a separate real identity-provider verification adapter is implemented and reviewed.
- Out of scope: Identity-provider deployment, OIDC/SAML protocol implementation, account provisioning and live API exposure.
- Touches: owner-approved authorization module, tests/, ARCHITECTURE.md, docs/access-control.md, CHANGELOG.md
- Size: M

## Step 6: Surfaces: API, dashboard, integrations

### Phase 4 — Surfaces: API, dashboard, integrations

Goal: make the persisted data usable by people and systems beyond a Check Run. Keep the gate, CLI and Action as first-class surfaces — this adds to them.

- A REST API (and/or GraphQL) over findings, runs, suppressions and policy, plus data export (SARIF out, CSV/JSON).
- A web dashboard: posture over time, findings by repo / severity / age, SLA and overdue views, and a suppression-review queue.
- SCM breadth: inline PR comments (not only a Check Run), and parity across GitLab, Bitbucket and Azure DevOps.
- Notifications to Slack / Teams.
- Ticketing: create and sync issues in Jira / ServiceNow from findings, with status flowing both ways.

Done when: a real team triages findings through the API and dashboard and files a ticket from a finding.

Delivery mapping: F-6.1 preserves the previous code-scanning upload choice; F-6.2–F-6.5 start API access, exports, a read-only dashboard and one ticket connector. API mutations for suppressions/policy, GraphQL, suppression approval UI, inline PR comments, GitLab/Bitbucket/Azure DevOps parity, Slack/Teams, ServiceNow and bidirectional ticket sync are deferred into separate integration slices. No live team acceptance or ticket creation is authorized by these plans.

### F-6.1 Upload SARIF to code scanning from the Action

- Status: planned
- Needs owner: Should the Action upload SARIF itself? Choose one: (a) no, the Action stays tokenless and users upload with their own step (F-1.5); (b) yes, through a `github-token` input and the code scanning API, which needs `security-events: write` in the user's workflow and changes SECURITY.md's statement that the Action uses no token (an edit only Robin makes). The acceptance below is for option (b).
- Why: SECURITY.md "Command line and GitHub Action" says the Action uses no token, and README "GitHub Action" says it uses no other actions. Uploading needs a token with `security-events: write`, which changes the Action's trust boundary, so it needs Robin.
- Acceptance:
  - With `upload-sarif: "true"` and a `github-token`, the Action uploads the F-1.5 SARIF file once, after a complete scan, for the workflow's commit and ref; a mocked API test checks the request.
  - A scan that exits 2 uploads nothing.
  - The token reaches the step only through an environment variable, never appears in output, and is not in the scanner's environment: the runner's environment allowlist is unchanged.
  - An upload error makes the step fail, so a failed upload never looks like a passing check.
  - Without the input, the Action uses no token, as today.
  - Tests cover full scans and --base scans, missing tokens, a stale pre-existing SARIF file after exit 2, and preservation of the gate’s failure when a complete scan exits 1.
- Out of scope: uploading from the command line or the App; any other use of the token.
- Touches: action.yml, scan_repo.py or a new upload helper, tests, README.md, CHANGELOG.md; SECURITY.md by Robin
- Size: M

### F-6.2 Expose a read-only findings and runs API

- Status: planned
- Needs owner: Choose REST first or GraphQL first; the proposed slice is REST. Approve the authenticated API trust boundary and dependencies only after F-5.5 and the separately approved SSO adapter are complete.
- Why: ARCHITECTURE.md lists only /webhook, /health and /ready; stored findings are not accessible to a team. Depends on F-4.1 and F-5.2.
- Acceptance:
  - Offline TestClient contract tests list findings and runs for the authenticated tenant, with stable pagination, documented JSON fields and repo/severity/status filters.
  - Missing identity returns 401; forbidden tenant/role access returns 403 without data. Invalid filters or cursors return a documented 4xx response, not an unfiltered result.
  - The API reference specifies every response field and error for these read routes; no write route, webhook payload or credential is exposed.
- Out of scope: GraphQL, API mutations, public deployment, token issuance and suppression/policy editing endpoints.
- Touches: app.py or owner-approved API module, tests/, docs/api.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-6.3 Export stored findings as SARIF, CSV and JSON

- Status: planned
- Needs owner: Approve authenticated bulk export, tenant limits and handling of source-derived text after F-6.2. Exports must preserve tenant isolation and existing scan output compatibility.
- Why: README can emit only current-run JSON/Markdown; persisted data needs portable exports. F-1.1 already supplies the SARIF writer.
- Acceptance:
  - Offline tests export one complete tenant-scoped fixture run to SARIF using F-1.1 and to CSV/JSON with documented fields for identity, priority, status and provenance; row/result counts match the authorized findings.
  - CSV tests cover commas, quotes, newlines and spreadsheet formula prefixes without executing cell content; JSON and SARIF remain parseable and retain escaped source text.
  - Unauthorized export, invalid selection or a storage error produces no success artifact. Existing CLI JSON fields are not renamed or removed.
- Out of scope: Cross-tenant exports, scheduled delivery, external storage and report uploads.
- Touches: export helpers, tests/, docs/api.md, README.md, CHANGELOG.md
- Size: M

### F-6.4 Show a read-only posture dashboard

- Status: planned
- Needs owner: Approve a UI surface and rendering approach after F-6.2 and the SSO adapter; any frontend dependency requires its own approval. This first slice is read-only.
- Why: The current user surfaces are console, job summary and Check Run; no aggregate finding history is visible. F-4.5 supplies age and overdue values.
- Acceptance:
  - An offline synthetic two-run dataset renders posture over time and findings grouped by repository, severity and age, with SLA/overdue values matching F-4.5 calculations.
  - UI tests exercise an empty tenant, populated tenant and API failure; failures show an error rather than a clean posture. Source-derived names and messages are escaped.
  - A viewer cannot see another tenant’s counts or records. The page exposes an accepted-risk review list without approval controls, and documents that decision mutations are a later slice.
- Out of scope: Suppression approval UI, policy editor, new authentication flows, live hosting and a new frontend stack without approval.
- Touches: owner-approved UI files, tests/, docs/dashboard.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

### F-6.5 Create one Jira ticket from a finding

- Status: planned
- Needs owner: Choose Jira first or ServiceNow first; this proposed slice is Jira. Approve outbound integration credentials, destination allowlisting, tenant authorization and the content allowed in tickets.
- Why: README ends at reporting a finding; no ticketing integration exists. A small connector establishes a reviewable outbound boundary before bidirectional synchronization.
- Acceptance:
  - Offline mocked HTTP tests create a Jira ticket for one authorized finding and store its external ID; retrying the same request returns the stored mapping without a duplicate ticket.
  - Unauthorized tenant access, an unapproved destination and malformed input make no HTTP request. Timeout, rate-limit and non-success responses return an explicit failed/pending state, never a successful ticket mapping.
  - The payload contains only the approved fields, and logs contain no credential or source snippet. A guide states precisely what is sent and how an operator revokes the integration.
- Out of scope: Live tickets, ServiceNow, bidirectional status sync, notifications and automatic bulk filing.
- Touches: owner-approved ticket connector, tests/, docs/integrations/jira.md, ARCHITECTURE.md, CHANGELOG.md
- Size: M

## Step 7: Scale and reliability

### Phase 5 — Scale and reliability

Goal: support many organizations and repositories with high availability. You already have the right primitives — SHA-based dedupe, at-least-once processing, backoff — so this is mostly about horizontal capacity and a sturdier datastore.

- Add a Postgres tier for the datastore while keeping SQLite for self-hosted / SMB installs; write migrations.
- Move to a queue that allows multiple concurrent workers (you cap at one worker per queue today), with backpressure and a dead-letter path; preserve your existing idempotency.
- Run horizontal, autoscaling scanner workers with ephemeral isolated execution (containers or Kubernetes jobs).
- Make web and worker highly available: readiness, graceful drain, no job lost on failover.
- Add load and soak testing and a capacity model.

Done when: a load test passes at the target throughput and a failover loses no jobs.

Delivery mapping: F-7.1–F-7.5 separate datastore/queue contracts, graceful drain, capacity modeling and HA design. The Postgres runtime adapter and migrations, production multi-worker claims/backpressure/dead-letter processing, autoscaling deployment and actual load/soak/failover runs are deferred owner-approved slices. Model results and design documents do not meet the real throughput/failover gate.

### F-7.1 Specify the Postgres schema and migration contract

- Status: planned
- Needs owner: If F-3.5 chose a Postgres tier, approve its schema, supported server/driver versions and migration/rollback policy. SQLite-only selection requires a roadmap correction before this item proceeds.
- Why: ARCHITECTURE.md limits durable storage to single-host SQLite; the Phase 2 schema must have an explicit migration contract before a second backend is built.
- Acceptance:
  - A documentation PR maps every finding/run/tenant table, key, unique constraint and transaction boundary from the selected SQLite schema to Postgres and includes forward/rollback examples.
  - Offline review checks an inventory of populated, empty, duplicate and interrupted migration fixtures with expected record counts and tenant boundaries; a compatibility matrix names which store contract tests the later adapter must pass.
  - The document states that no production migration or Postgres implementation is complete and names a separate driver/backend assignment as a prerequisite for HA deployment.
- Out of scope: New database dependency, live Postgres, production migrations and changing the SQLite default.
- Touches: docs/postgres-migration.md, ARCHITECTURE.md
- Size: S

### F-7.2 Specify concurrent queue claims and backpressure

- Status: planned
- Needs owner: Approve a multi-worker queue design and backend after F-7.1, including lease expiry, queue bounds, dead-letter retention and tenant fairness. Removing the existing one-worker lock is not authorized by a design merge.
- Why: worker.py uses an exclusive queue lock; ARCHITECTURE.md describes at-least-once processing, retry/backoff and fixed queue limits.
- Acceptance:
  - A state-machine specification gives claim, heartbeat, retry, lease-expiry, terminal-failure and dead-letter transitions, with an offline executable model using a fake clock and two simulated workers.
  - Model tests show one active lease per job, idempotent completion after redelivery, no job lost after a worker crash, and explicit refusal/backpressure at the approved capacity.
  - The plan preserves current dedupe and rate-limit behavior or names each owner decision needed to change it. The production worker and its one-worker limit remain unchanged in this slice.
- Out of scope: Production concurrent workers, queue deployment, changing limits, external brokers or new dependencies.
- Touches: docs/queue-concurrency.md, tests/ queue model fixtures
- Size: M

### F-7.3 Drain a worker without losing claimed jobs

- Status: planned
- Needs owner: Approve durable worker shutdown behavior and its interaction with leases and readiness. Depends on the selected queue contract in F-7.2; deployment changes remain owner work.
- Why: ARCHITECTURE.md documents restart recovery but not an explicit graceful-drain contract; reliable rollouts need one before HA.
- Acceptance:
  - Offline tests send a synthetic shutdown request: the worker stops claiming, finishes or returns its in-flight job according to a documented bounded grace period, and can restart without losing the job.
  - Fake-clock tests cover shutdown before claim, during scan and during Check completion; replay preserves the existing idempotency/recovery contract and cannot turn an incomplete scan into success.
  - Readiness indicates draining and fails for new work while liveness remains available. Scanner cleanup is asserted for grace-period expiry.
- Out of scope: Changing deployment supervisors, multiple live workers, autoscaling or claiming exactly-once GitHub delivery.
- Touches: worker.py, job_store.py, app.py readiness, tests/, ARCHITECTURE.md, docs/operator-runbook.md, CHANGELOG.md
- Size: M

### F-7.4 Add a bounded capacity and latency model

- Status: planned
- Needs owner: Approve a target workload, throughput and end-to-end latency budget, plus a separate environment/time/cost budget for any real load or soak test.
- Why: SECURITY.md says timeouts are per step; deploy/README.md specifies a small single-host target without a measured capacity model.
- Acceptance:
  - A documented synthetic workload specifies job counts, file counts/sizes, tenant distribution, arrival rate and scanner-duration distribution; a fake-clock offline harness produces deterministic queue-wait and end-to-end latency percentiles.
  - Boundary tests reject workloads exceeding the configured local harness budget. The report compares measured model output with the approved target and reports failure when the target is missed.
  - A reproducible load/soak plan names hardware, duration, concurrency, target throughput and failure criteria. It clearly labels simulated results and leaves real-host results NOT_RUN until owner execution.
- Out of scope: Unbounded stress runs, real-host load, spending, changing production limits or claiming model output as capacity proof.
- Touches: tests/ capacity model, docs/performance.md, docs/operator-runbook.md
- Size: M

### F-7.5 Specify isolated horizontal workers and HA failover

- Status: planned
- Needs owner: Choose containers on fixed hosts or Kubernetes jobs, and approve the deployment trust boundary, hosting cost and HA datastore/queue prerequisites after F-2.1, F-7.1 and F-7.2.
- Why: ARCHITECTURE.md documents one host and worker per queue, plus strict scanner container isolation that scaling must preserve.
- Acceptance:
  - A deployment design records web/worker replicas, ephemeral scanner lifetime, readiness, drain, failover and autoscaling signals, while retaining no egress, read-only mounts, scoped credentials and resource bounds.
  - An offline failure table covers web loss, worker loss, datastore outage, duplicate delivery and scale-down; each row names expected queue state, Check state, recovery action and evidence required to prove no lost jobs.
  - The plan distinguishes future real-host failover/load evidence from model tests and names the owner-run acceptance gate before any HA claim.
- Out of scope: Deploy manifests, Kubernetes installation, host provisioning, production failover and changes to scanner limits.
- Touches: docs/ha-design.md, ARCHITECTURE.md
- Size: S

## Step 8: Enterprise operations and compliance

### Phase 6 — Enterprise operations and compliance

Goal: the operational and trust surface an enterprise needs to adopt and keep the tool. Much of this hardens what you already do well.

- Observability: OpenTelemetry metrics and traces, Grafana/Prometheus dashboards, real alerting and on-call paging (this closes your documented "there are no alerts" gap), and SLOs.
- Audit logging: a tamper-evident record of scans, suppressions, policy changes and admin actions.
- Data governance: retention and residency controls and a documented data map (you already keep tokens and payloads out of logs — formalize it).
- Supply-chain trust: signed releases and an SBOM on every release (cosign / SLSA provenance), a scheduled dependency audit in CI (you already hit advisory binds — automate detection), and a vulnerability-disclosure process with response SLAs built on your existing SECURITY.md.
- Compliance readiness: a refreshed threat model, a third-party penetration test, a SOC 2-oriented control mapping, and operator runbooks.

Done when: the service emits metrics and alerts, every release ships signed with an SBOM, and a control mapping plus an external pen test are in place.

Delivery mapping: F-8.1–F-8.5 cover operational signal contracts, audit integrity, data governance, release assurance and control mapping. Telemetry exporters, Grafana/Prometheus dashboards, paging, retention enforcement/residency infrastructure, release signing/provenance automation, scheduled dependency/image audits and an external penetration test remain separately approved work. The final gate requires real evidence, not these plans alone.

### F-8.1 Define operational signals and alert contracts

- Status: planned
- Needs owner: Approve metrics/traces fields, SLO targets, telemetry retention/export destinations and paging ownership. OpenTelemetry/Prometheus/Grafana dependencies, dashboards and alert infrastructure require separate owner work.
- Why: deploy/README.md says there are no alerts; SECURITY.md limits logs to avoid credential and source disclosure.
- Acceptance:
  - A signal contract lists queue age, failed jobs, scan duration, readiness and trace boundaries, including units, bounded label sets and exclusions for tokens, payloads and source text.
  - Offline fake-clock/log fixtures map healthy, stale-worker, terminal-failure and recovery events to expected metric/alert states and assert the owner-approved SLO window and thresholds.
  - A runbook states the recipient role, escalation and recovery action for each alert and distinguishes contract tests from an installed exporter or live paging system.
- Out of scope: Adding telemetry dependencies, sending telemetry/pages, provisioning dashboards and claiming a live SLO.
- Touches: docs/observability.md, docs/operator-runbook.md, tests/ signal contract fixtures
- Size: S

### F-8.2 Make security decisions auditable with a hash chain

- Status: planned
- Needs owner: Approve audit event schema, access/retention controls and the trusted checkpoint model. A local hash chain detects alteration only relative to a protected checkpoint; external anchoring is a separate trust decision.
- Why: SECURITY.md warns about source-derived logs, while the new lifecycle and policy surfaces need actor-attributed history. Depends on F-4.3 and F-5.4.
- Acceptance:
  - Offline tests append scan, suppression, policy-change and admin-action events with actor, tenant, timestamp, event type and prior hash; reopen preserves order and chain verification.
  - Changing or deleting an interior event fails verification, and truncation fails against a supplied protected checkpoint. Documentation explicitly states the limit when the entire store and checkpoint can both be replaced.
  - Missing actor/tenant or a failed audit append rejects the protected mutation. Event payloads exclude tokens, webhook bodies and source text.
- Out of scope: External notarization, compliance certification, replacing operational logs and production storage migration.
- Touches: audit store and decision services, tests/, ARCHITECTURE.md, docs/audit.md, CHANGELOG.md
- Size: M

### F-8.3 Define retention, residency and the data map

- Status: planned
- Needs owner: Approve retention periods by data class, residency choices, deletion authority and treatment of audit/legal holds before any purge or relocation is implemented.
- Why: SECURITY.md asks operators to restrict access and retention; current deploy docs define only queue retention, not enterprise finding history.
- Acceptance:
  - A data map lists source files, findings, run metadata, queue identifiers, audit events and credentials with storage location, recipient, access role and deletion owner; it records that credentials and payloads must not enter logs.
  - A retention matrix gives an explicit duration or named hold rule for each stored class and a residency boundary for each export/integration.
  - Offline timestamp fixtures describe keep/delete/hold outcomes at each boundary and tests validate the proposed selector without deleting real records. The runbook labels actual purge and relocation as separately authorized operations.
- Out of scope: Deleting production data, changing queue retention, data export to a new region or legal compliance claims.
- Touches: docs/data-governance.md, tests/ retention selector fixtures, ARCHITECTURE.md
- Size: S

### F-8.4 Specify release provenance and recurring supply-chain checks

- Status: planned
- Needs owner: Approve signing identity, SBOM format, provenance level, dependency/image audit cadence and vulnerability response SLA. Workflow, release, deployment and SECURITY.md edits remain owner-only assignments.
- Why: CHANGELOG already follows SemVer and Keep a Changelog, but README distributes by clone; SECURITY.md promises no response time and deploy/README.md leaves the final image audit open.
- Acceptance:
  - A release checklist names wheel/image digests, signature verification, SBOM inventory, provenance fields and changelog-derived release notes, with synthetic valid/invalid evidence examples and expected verification outcomes.
  - A recurring audit plan names dependency and scanner-image inputs, cadence, responsible role and failure action; it never treats an unresolved audit as a successful release.
  - A disclosure-process proposal names private intake, acknowledgement/response deadlines chosen by Robin and escalation ownership, explicitly requiring owner changes to SECURITY.md before claiming those deadlines apply.
  - The document states that v2.1.1 is already released and that this item creates neither a tag, published package/image, signature nor scheduled workflow.
- Out of scope: Workflow edits, scheduled jobs, dependency/version changes, signing/publishing, release tags and SECURITY.md edits.
- Touches: docs/release-assurance.md, docs/disclosure-process-proposal.md
- Size: S

### F-8.5 Map controls and prepare external assurance

- Status: planned
- Needs owner: Approve the threat-model scope, external penetration-test scope/provider/budget and the control framework. SOC 2-oriented mapping is not certification or permission to test a live target.
- Why: ARCHITECTURE.md and SECURITY.md document current trust boundaries; enterprise scope adds storage, tenants and integrations that need explicit review.
- Acceptance:
  - A refreshed threat model maps each new data flow and trust boundary to the implemented control, offline regression test or unresolved owner gate; no planned control is labeled deployed.
  - A SOC 2-oriented control matrix links access, change management, incident response, recovery and retention to evidence locations and responsible roles; missing evidence is explicit.
  - A penetration-test brief specifies authorized targets, exclusions, data handling, stop conditions and report/remediation ownership. The operator runbook index covers restart, recovery, incident triage and integration revocation.
  - External testing and the final Phase 6 gate remain NOT_RUN until separately commissioned evidence exists.
- Out of scope: Running a penetration test, live exploitation, purchasing assurance, certification and altering SECURITY.md.
- Touches: docs/threat-model.md, docs/control-mapping.md, docs/assurance-plan.md, docs/operator-runbook.md
- Size: M

## Cross-cutting tracks

These run across every phase rather than in sequence:

- Packaging and release. pyproject.toml, a versioned PyPI package and pinned CLI, a signed container image, and automated release notes from your existing changelog.
- Testing. Keep the fail-closed, 202-test discipline. Add contract tests per SARIF adapter, integration tests against a GitHub sandbox, property tests for the triage logic, and the load tests from Phase 5 — all behind CI coverage gates.
- Documentation. Your docs are already a strength. Add a docs site, per-integration guides, a consolidated operator runbook (from your deploy/* notes), and an API reference once Phase 4 lands.
- Security of the tool itself. Keep the threat model current, automate dependency auditing in CI (you repeatedly hit advisory binds — make them visible), and audit the scanner image on a schedule.
- Performance budgets. You enforce per-file 1 MiB limits and timeouts; add end-to-end latency budgets as surfaces and tenants grow.

### Native rule coverage

Needs owner: after F-2.5, should native rule coverage come before additional scanner adapters or after them? These three candidates from the previous proposal are deliberately deferred, with no scheduled F IDs until Robin approves their priority and a roadmap PR places them in an eligible step. They change no gate threshold and add no language.

- **Log injection:** `py-log-injection` and `js-log-injection`, WARNING/medium, CWE-117. README's NodeGoat "Missed" list provides the evidence. Preserve the proposed within-function request-to-logging coverage for Python `logging` and Express-to-`console`, including later arguments; live positive/negative fixtures must distinguish request text from literals, numeric conversion, removed line breaks and JSON serialization. No cross-function flow or extra logging libraries.
- **Nested-quantifier regex:** `py-regex-nested-quantifier` and `js-regex-nested-quantifier`, WARNING/medium, CWE-1333. README names the missed ReDoS-prone regex. Preserve literal nested-repetition cases in Python `re`, JS regex literals and `RegExp`; safe non-nested patterns, runtime-built patterns and unrelated strings must remain unflagged. No general claim to decide regex complexity.
- **FastAPI/Starlette request data:** extend `py-sql-injection`, `py-path-traversal` and `py-ssrf` to `request.query_params` and `request.path_params`. README currently names Flask/Django. Preserve positive request-to-sink cases and negative numeric, parameterized-query, safe-filename and fixed-host examples; no `py-xss`, typed handler parameters or new rule IDs.

Each scheduled rule slice must include live positive/negative tests on the approved pinned scanner (currently Semgrep 1.79.0), unchanged planted-P1 selfcheck, the corresponding `deploy/validate_scanner.py` **rule samples**, and all affected rule counts and README coverage statements. Needs owner: any change to that deployment file beyond an added or changed service-owned rule sample, including scanner compatibility, validation logic or harness changes. This is not a blanket exception for deployment work.

Track mapping: packaging starts at F-2.4; signing, SBOMs, audit cadence and release notes are specified by F-8.4. Adapter contracts belong to F-3.1–F-3.4, capacity/latency to F-7.4, and threat modeling to F-8.5. Documentation accompanies every item; F-2.3/F-6.2 establish the runbook/API reference. A hosted docs site, broader per-integration guides, GitHub sandbox integration tests, property-test expansion and CI coverage gates are deferred until their surfaces and owner-approved workflow scope exist. These cross-cutting tracks do not permit skipping the current step.

## Where to start

Do first, in weeks, not months:

- Phase 0 go-live + a real release. This converts an impressive codebase into a running service and is the biggest single credibility jump — and it's mostly finishing work you've already designed.
- Phase 1 SARIF ingestion. The defining architectural move; it unlocks multi-tool and multi-language coverage cheaply and reframes the product.
- Then Phase 2 (persistence), because every enterprise feature after it — dashboards, SLAs, suppression review, per-team policy — depends on stored findings.

## Big decisions

Big decisions to settle early, because they change later scope:

- Product framing: "Semgrep reviewer" vs. "triage/gate layer over any scanner." Phase 1 commits you — decide before you build it.
- Datastore path: SQLite-only self-host vs. a Postgres tier. This shapes the Phase 2/3/5 schema.
- Scanner version bind: resolve the Semgrep 1.79.0 pin (or adopt Opengrep) before you stand durable mode up on it.
- Hosting and trust: your deploy docs gate a paid host or tunnel on approval. Decide whether this stays a self-hosted lab artifact or aims at a hosted multi-tenant service — that choice changes the scope of Phases 3, 5 and 6 substantially.

For a portfolio aimed at AppSec and offensive-security roles, Phases 0–2 already read as enterprise-grade engineering on their own; Phases 3–6 are the full product build and are a multi-quarter effort.

Decision gates: hosting and trust is F-2.1; the durable scanner is F-2.2; product framing is F-2.5, before Step 3; the datastore path is F-3.5, before Step 4. Their dependent items remain blocked until the respective explicit owner decisions. "Where to start" retains Robin's enterprise sequence; the five quick wins in Step 1 intentionally precede it.
