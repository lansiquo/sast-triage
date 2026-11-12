# sast-triage: roadmap to an enterprise-grade SAST platform

Owner: Robin. Adopted 2026-11-11.

Owner-approved order of work for sast-triage. Items are built one at a time, lowest step first.
Status changes only through merged pull requests.

sast-triage is a diff-aware SAST gate for Python, JavaScript and TypeScript (CLI, GitHub Action, GitHub App; v2.4.1). This roadmap takes it to a multi-tool, multi-tenant platform: five quick wins (Step 1), then Robin's Phases 0–6 (Steps 2–8). Each item is one week-sized PR.

Merging approves order and acceptance, never a `Needs owner` decision or any dependency, deployment, workflow, hosting, release or trust-boundary change. "Done when" gates need real evidence, and the next step waits for them. Steps 2–8 have one row per item; full Why, Out of scope and Touches arrive by roadmap PR before a step becomes current.

## Where it stands today

- One engine, three surfaces; findings are new or pre-existing against the base, ranked P1–P3; only a new P1 fails the gate.
- Fail closed everywhere; 41 service-owned rules (8 taint-mode); 204 tests on Python 3.11–3.14.

| Dimension | Today | Enterprise bar |
|---|---|---|
| Deployment | Durable mode never run live | Running service, recovery proven on a real host |
| Scanner coverage | Semgrep; Python/JS/TS | Many scanners and languages via a common format |
| Persistence | Check Run and job summary per PR | Findings stored and tracked over time |
| Finding lifecycle | None | First-seen/fixed/reintroduced, audited suppression, SLA |
| Tenancy and policy | One repo and installation; gate fixed at new P1 | Many tenants, per-team policy-as-code |
| Access control | None (no UI or API) | SSO and RBAC |
| Surfaces | CLI, Action summary, GitHub Checks | API, dashboard, SCM and ticketing integrations |
| Distribution | Clone and run | Signed, versioned package, image and SBOM |
| Observability | No alerts | Metrics, traces, alerting, audit log |
| Scale | Single-host SQLite, one worker per queue | HA datastore, horizontal workers |

## Where to start

First, in weeks, not months: Step 2, the biggest credibility jump; Step 3, the defining architectural move; then Step 4, which every later enterprise feature needs. Steps 2–4 stand on their own; Steps 5–8 are a multi-quarter build.

## Step 1: Quick wins (no owner decisions)

Goal: Users can export SARIF, diagnose missing base history and use the existing CLI controls and reports through the tokenless Action.

### F-1.1 SARIF output from the command line (`--sarif FILE`)

- Status: done
- Why: README offers only the console report, `--json` and `--markdown`, and the Action only a job summary, so findings can't reach code scanning or other SARIF tools. CHANGELOG 0.1.2's upload workflow was removed in commit `39da7e6`, before v1.0.0. Serializing the existing triage result, this defines the finding model reused by F-3.1–F-3.4.
- Acceptance:
  - `scan_repo.py DIR --sarif FILE` writes SARIF 2.1.0 JSON (`"version": "2.1.0"`): one run, `tool.driver.name` `sast-triage`, each reported rule ID once in `tool.driver.rules`, one result per `--json` finding for the same input, in the same order.
  - Each result has `ruleId`, the forward-slash relative path as `locations[0].physicalLocation.artifactLocation.uri`, `region.startLine`, `region.endLine`, `fingerprint` under `partialFingerprints`, and `properties` `priority`, `new`, `new_because`, `cwe` equal to `--json`.
  - `level` follows Check Run annotations: `error` for a new P1, `warning` for a new P2, `note` otherwise.
  - With `--base REF`, `properties.new` is false for pre-existing and true for new findings, matching `--json`.
  - Nothing to scan: exit 0, FILE holds one run with no results.
  - Scanner error, git error or file over 1 MiB: exit 2, FILE not created, an existing FILE unchanged.
  - `--sarif` changes no exit status, console report, `--json` or `--markdown` output.
  - Unwritable destination or invalid option: exit 2, no partial artifact. Tests cover full and `--base` scans.
- Out of scope: uploading; an Action input (F-1.5); new `--json` fields.
- Touches: scan_repo.py, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: M

### F-1.2 Actionable errors when the `--base` history is missing

- Status: done
- Why: Without base history (`fetch-depth: 0`), `scan_repo.py` says only "cannot diff against origin/main, no result issued." and "git rev-parse failed", or git's "no merge base" text, with no hint.
- Acceptance:
  - Without the ref, `scan_repo.py DIR --base origin/missing` exits 2 with no result; stderr names the ref, says it is not a commit in this checkout, and mentions `git fetch` and `fetch-depth: 0`.
  - In a shallow clone (`git clone --depth 1`) whose base ref exists but whose merge base with `HEAD` is missing, it exits 2 with no result; stderr says no merge base was found and mentions `fetch-depth: 0`.
  - A `--base` value starting with `-` is still refused with exit 2 before git runs.
  - A successful `--base` scan's exit status and output are unchanged.
- Out of scope: fetching history (scans make no network calls); the Action's checkout instructions.
- Touches: scan_repo.py, tests/test_scan_repo.py, README.md ("Exit codes", if wording changes), CHANGELOG.md
- Size: S

### F-1.3 Action input for the scan time limit

- Status: done
- Why: `--timeout` (default 300 seconds) is the only way to give a large scan more time, but `action.yml` has only `path` and `base` inputs, so a slower Action scan exits 2.
- Acceptance:
  - `action.yml` declares an optional `timeout` input, default `""`.
  - With `timeout` empty the Scan step runs `scan_repo.py` with today's arguments (no `--timeout`); `timeout: 600` adds `--timeout 600`. A test runs the step's script from `action.yml` with a stub interpreter and checks both.
  - The input reaches the script only through an environment variable, like `path` and `base`: `${{ inputs.timeout }}` never appears in a `run` script.
  - A value that is not a whole number exits 2 with no result, as `scan_repo.py --timeout abc` does.
  - README "GitHub Action" documents the input and its default.
  - Tests repeat the empty, valid and invalid cases with a base ref and with `base: none`; base arguments and gate result are unchanged.
- Out of scope: the App's scan timeout; the values `--timeout` accepts; the Action's install step and permissions.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

### F-1.4 Pull request annotations from the command line and the Action

- Status: done
- Why: The App annotates up to 200 findings, P1 first; the Action's summary names at most 10 new P1 findings and no others (`summarize_findings` in `analyzers/semgrep_runner.py`), so users must read the log.
- Acceptance:
  - `scan_repo.py DIR --github-annotations` prints, after the report, one GitHub workflow command per finding with `file`, `line`, `endLine` and `title`: `::error` for a new P1, `::warning` for a new P2, `::notice` otherwise, the App's levels.
  - At most 200 commands, in the App's annotation order (P1 first).
  - Text is escaped as GitHub requires (`%`, carriage return, line feed in messages; also `:` and `,` in properties): a path holding a comma, colon, percent sign and line feed yields exactly one command line, with the escaped path.
  - `--github-annotations` with `--json` exits 2 with a usage error.
  - A scanner or git error exits 2 and prints no workflow command.
  - Without the flag, output is unchanged.
  - `action.yml` has an optional `annotations` input, default `"false"`; `"true"` adds the flag; any other value exits 2 before scanning. It reaches the script only through an environment variable.
  - A `--base` fixture with one new and one pre-existing finding yields the matching levels without changing the gate. Hostile finding text cannot create an extra workflow command.
- Out of scope: Check Runs from the Action (it uses no token); the App's annotations.
- Touches: scan_repo.py, analyzers/semgrep_runner.py (annotation levels only), action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: M

### F-1.5 Action input that writes SARIF

- Status: done
- Why: After F-1.1 the CLI writes SARIF but the Action can't request it. The Action uses no token (SECURITY.md) and no other actions (README), so the user's own workflow step must upload.
- Acceptance:
  - `action.yml` has an optional `sarif` input, default `""`; when set, the Scan step passes `--sarif` with that path; when empty, arguments are unchanged. It reaches the script only through an environment variable.
  - When the scan exits 2, no file is created at that path and an existing file is unchanged. The documented upload step checks for a completed exit-0 or exit-1 scan, so it never uploads a stale file.
  - README "GitHub Action" shows a separate upload step in the user's workflow, pinned to a full commit SHA, notes it needs `security-events: write`, and states that sast-triage itself still uses no token and no other actions.
  - Tests cover full and `--base` scans, paths with spaces, and invalid or unwritable paths (exit 2, no partial artifact).
- Out of scope: uploading from the Action (F-6.1); the Action's permissions.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

## Step 2: Go live, and ship a real release

Goal: Run the designed durable mode as a verified service and make the project installable.

Done when: a real PR is scanned end to end in durable mode on the host, worker recovery is proven against GitHub, and a tagged release ships a signed image and SBOM.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-2.1 | Decide hosting and trust | S | planned | Needs owner | A decision document records one option and each yes/no. |
| F-2.2 | Decide the durable scanner path | S | planned | Needs owner | A decision record names one scanner, exact version and required compatibility evidence. |
| F-2.3 | Make the go-live evidence checklist reviewable | M | planned | Needs owner | Every required release verification has an expected result and a NOT_RUN evidence field. |
| F-2.4 | Prepare a locally installable CLI package | M | planned | Needs owner | An offline-built wheel's entry point scans `tests/fixtures/project` with exit 1. |
| F-2.5 | Decide the product framing before Phase 1 | S | planned | Needs owner | A decision document records one choice and an in/out scope list. |

## Step 3: Become a triage platform (SARIF ingestion)

Goal: Ingest SARIF 2.1.0 from any scanner and apply the same new/pre-existing, P1–P3 and gate logic.

Done when: two scanners' SARIF (for example Semgrep and CodeQL) pass through one gate with new/pre-existing labels intact.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-3.1 | Parse SARIF into the shared finding model | M | planned | Needs owner | Semgrep and CodeQL fixtures load into F-1.1 fields; malformed input yields no findings. |
| F-3.2 | Define explicit severity mappings for imported results | M | planned | Needs owner | Equivalent high-severity Semgrep and CodeQL fixtures rank identically; unknown severities fail. |
| F-3.3 | Carry diff-aware labels through imported findings | M | planned | Needs owner | A finding absent from the base stays new despite a matching `partialFingerprint`. |
| F-3.4 | Triage supplied Semgrep and CodeQL reports from the CLI | M | planned | Needs owner | Import exits 1 for a new P1, 0 for a complete clean report, 2 for invalid input. |
| F-3.5 | Decide the finding datastore path before Phase 2 | S | planned | Needs owner | A decision record names one datastore path and defines stable finding identity. |

## Step 4: Persistence and finding lifecycle

Goal: Store findings and runs to track security posture over time.

Done when: a finding's lifecycle (first-seen, fixed, reintroduced) persists across runs with an auditable suppression trail.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-4.1 | Persist completed runs and stable finding records | M | planned | Needs owner | Replaying a completed run duplicates no finding and keeps first-seen. |
| F-4.2 | Track fixed and reintroduced findings | M | planned | Needs owner | Only a complete same-scope run can mark an absent finding fixed. |
| F-4.3 | Record expiring accepted-risk decisions | M | planned | Needs owner | A fake clock shows expiry restores unsuppressed behavior; `nosemgrep` creates no record. |
| F-4.4 | Adopt an explicit branch baseline | M | planned | Needs owner | After adopting a complete run, only an additional finding is new. |
| F-4.5 | Compute finding age and overdue status | S | planned | Needs owner | Fake-clock tests cover just before, at and after each deadline. |

## Step 5: Multi-tenancy, policy-as-code and access control

Goal: Lift the one-repo, one-installation limit; make gate policy and access configurable per team.

Done when: two tenants run fully isolated, each with its own enforced gate policy and role-controlled access.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-5.1 | Opt-in gate on new P2 findings | M | planned | Needs owner | If approved: `scan_repo.py DIR --fail-on P2` exits 1 on a new P1 or P2, else 0. |
| F-5.2 | Enforce tenant isolation in stored findings | M | planned | Needs owner | Tenant A cannot read or mutate tenant B's data. |
| F-5.3 | Route App jobs by approved installation and repository | M | planned | Needs owner | Each token is narrowed to its job's one repository; unknown pairs enqueue nothing. |
| F-5.4 | Load centrally governed team gate policy | M | planned | Needs owner | Missing or invalid policy fails closed; repository-authored policy cannot override it. |
| F-5.5 | Define and enforce the tenant role boundary | M | planned | Needs owner | Missing identity, unknown roles and tenant mismatch are denied, state unchanged. |

## Step 6: Surfaces: API, dashboard, integrations

Goal: Make persisted data usable by people and systems beyond a Check Run.

Done when: a real team triages findings through the API and dashboard and files a ticket from a finding.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-6.1 | Upload SARIF to code scanning from the Action | M | planned | Needs owner | If approved: one mocked upload after a complete scan; exit 2 uploads nothing. |
| F-6.2 | Expose a read-only findings and runs API | M | planned | Needs owner | Missing identity returns 401; a forbidden tenant or role returns 403 without data. |
| F-6.3 | Export stored findings as SARIF, CSV and JSON | M | planned | Needs owner | Export counts match authorized findings; unauthorized export writes no artifact. |
| F-6.4 | Show a read-only posture dashboard | M | planned | Needs owner | An API failure shows an error, never a clean posture. |
| F-6.5 | Create one Jira ticket from a finding | M | planned | Needs owner | A mocked retry returns the stored ticket mapping, no duplicate. |

## Step 7: Scale and reliability

Goal: Support many organizations and repositories with high availability.

Done when: a load test passes at the target throughput and a failover loses no jobs.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-7.1 | Specify the Postgres schema and migration contract | S | planned | Needs owner | Every table, key and constraint maps from SQLite to Postgres with rollback examples. |
| F-7.2 | Specify concurrent queue claims and backpressure | M | planned | Needs owner | A two-worker fake-clock model keeps one lease per job and loses none after a crash. |
| F-7.3 | Drain a worker without losing claimed jobs | M | planned | Needs owner | After a synthetic shutdown the worker stops claiming and restarts without losing its job. |
| F-7.4 | Add a bounded capacity and latency model | M | planned | Needs owner | A fake-clock harness gives deterministic latency percentiles and fails on a missed target. |
| F-7.5 | Specify isolated horizontal workers and HA failover | S | planned | Needs owner | A failure table names queue state, Check state and recovery per loss scenario. |

## Step 8: Enterprise operations and compliance

Goal: Provide the operational and trust surface an enterprise needs.

Done when: the service emits metrics and alerts, every release ships signed with an SBOM, and a control mapping and an external pen test are in place.

| ID | Item | Size | Status | Owner | Acceptance |
|---|---|---|---|---|---|
| F-8.1 | Define operational signals and alert contracts | S | planned | Needs owner | Fixtures map healthy, stale-worker, terminal-failure and recovery events to expected alert states. |
| F-8.2 | Make security decisions auditable with a hash chain | M | planned | Needs owner | Changing or deleting an interior event fails chain verification. |
| F-8.3 | Define retention, residency and the data map | S | planned | Needs owner | Timestamp fixtures give keep, delete or hold at each boundary. |
| F-8.4 | Specify release provenance and recurring supply-chain checks | S | planned | Needs owner | Valid and invalid evidence examples have expected verification outcomes. |
| F-8.5 | Map controls and prepare external assurance | M | planned | Needs owner | The threat model maps each new data flow to a control, test or open owner gate. |

## Cross-cutting tracks

- Packaging and release: versioned package, pinned CLI, signed image, changelog-derived release notes (F-2.4, F-8.4).
- Testing: fail-closed discipline plus adapter contract, GitHub sandbox, property and load tests behind CI coverage gates.
- Documentation: docs site, integration guides, operator runbook, API reference.
- Security of the tool: current threat model; scheduled dependency and scanner-image audits.
- Performance budgets: end-to-end latency budgets beside the 1 MiB and timeout limits (F-7.4).

### Native rule coverage

Needs owner. These three candidates from the previous proposal are deliberately deferred, with no scheduled F IDs until a roadmap PR schedules them. They change no gate threshold and add no language.

- **Log injection:** `py-log-injection` and `js-log-injection`, WARNING/medium, CWE-117. README's NodeGoat "Missed" list provides the evidence. Preserve the proposed within-function request-to-logging coverage for Python `logging` and Express-to-`console`, including later arguments; live positive/negative fixtures must distinguish request text from literals, numeric conversion, removed line breaks and JSON serialization. No cross-function flow or extra logging libraries.
- **Nested-quantifier regex:** `py-regex-nested-quantifier` and `js-regex-nested-quantifier`, WARNING/medium, CWE-1333. README names the missed ReDoS-prone regex. Preserve literal nested-repetition cases in Python `re`, JS regex literals and `RegExp`; safe non-nested patterns, runtime-built patterns and unrelated strings must remain unflagged. No general claim to decide regex complexity.
- **FastAPI/Starlette request data:** extend `py-sql-injection`, `py-path-traversal` and `py-ssrf` to `request.query_params` and `request.path_params`. README currently names Flask/Django. Preserve positive request-to-sink cases and negative numeric, parameterized-query, safe-filename and fixed-host examples; no `py-xss`, typed handler parameters or new rule IDs.

Each scheduled rule slice must include live positive/negative tests on the approved pinned scanner (currently Semgrep 1.79.0), unchanged planted-P1 selfcheck, the corresponding `deploy/validate_scanner.py` **rule samples**, and all affected rule counts and README coverage statements. Any other change to that deployment file: Needs owner.
