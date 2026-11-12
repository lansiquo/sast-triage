# Decision 0003: the product framing

- Status: decided
- Date: 2026-11-12
- Decided by: Robin (owner)
- Roadmap item: F-2.5, "Decide the product framing before Phase 1" ([ROADMAP.md](../../ROADMAP.md), Step 2)

This record says what kind of product sast-triage is, and lists what is in scope and what is out of scope for now, so that Step 3 of the roadmap (Phase 1, SARIF ingestion) has a fixed boundary. It records a decision. It changes no code, dependency or scan result, and it authorizes no action: see "Not decided here / not authorized" below.

## Decision

sast-triage is a triage and gate layer over any scanner. It labels findings new or pre-existing, ranks them and gates pull requests. It is not a scanner of its own.

- **In scope:** imported SAST results, as SARIF.
- **Out of scope for now:** new languages and secrets scanning.
- **SCA:** stays in [sca-triage](https://github.com/lansiquo/sca-triage).

Finding the problems in the code is the scanner's work. What sast-triage adds is the same whichever scanner reported a finding: whether the change introduced it, how urgent it is, and whether the gate passes.

## In scope

| In scope | Tied to |
|---|---|
| Imported SAST results, as SARIF 2.1.0 | [ROADMAP.md](../../ROADMAP.md), Step 3 goal: "Ingest SARIF 2.1.0 from any scanner and apply the same new/pre-existing, P1–P3 and gate logic." Items F-3.1 to F-3.4. Not built yet. |
| The existing Semgrep path: Semgrep, pinned at 1.79.0, with the 41 service-owned rules in `trusted_rules.py`, on Python, JavaScript and TypeScript files | [README.md](../../README.md), "Rules"; [ARCHITECTURE.md](../../ARCHITECTURE.md), "Components"; [decision 0002](0002-durable-scanner.md) for durable mode |
| The same new or pre-existing labels | README.md, "How triage works" ("New or pre-existing") and "Scope and limits" ("New is judged file by file"); F-3.3 for imported findings |
| The same P1–P3 ranking | README.md, "How triage works" (the P1, P2 and P3 table and "Test code"); F-3.2 for imported results |
| The same gate | README.md, "How triage works": "It fails only when a finding is both new and P1. Scanner errors and partial results also fail it; only a complete scan can pass." Also "Exit codes"; F-3.4 for imported reports |
| All three surfaces: the command line, the GitHub Action and the GitHub App | ARCHITECTURE.md, first paragraph; ROADMAP.md, "Where it stands today": "One engine, three surfaces". For imported reports, only the command line has a roadmap item (F-3.4). |

## Out of scope for now

"For now" means until a later owner decision. This record sets no date.

| Out of scope for now | Tied to |
|---|---|
| New languages. Today's languages are Python, JavaScript and TypeScript (`.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`) | ARCHITECTURE.md, "Out of scope": "Other languages". ROADMAP.md, "Native rule coverage": the deferred rule candidates "add no language". No roadmap item adds a language. |
| Secrets scanning | ARCHITECTURE.md, "Out of scope": "secrets detection". No roadmap item adds it. |
| SCA (dependency analysis), which stays in sca-triage | README.md, first section: sca-triage is the "SCA companion". ARCHITECTURE.md, "Out of scope": "dependency analysis", with a pointer to sca-triage. No roadmap item adds it. |

## Options not chosen

Each "Why not" uses only what the repository's own documents say.

**Becoming a full scanner:** its own detection engine, or its own rules for everything a scanner can find.

Why not: the roadmap's scheduled steps widen coverage by taking in other scanners' results: it describes the target as a "multi-tool, multi-tenant platform", Step 3's goal is to "Ingest SARIF 2.1.0 from any scanner", and no scheduled item adds detection of its own. The project's own detection is narrow: 41 rules "for high-signal patterns" that match within one file (README.md), with "data flow across functions or files" out of scope (ARCHITECTURE.md).

**Adding languages:** support for code other than Python, JavaScript and TypeScript.

Why not: ARCHITECTURE.md lists "Other languages" as out of scope, and the rule candidates the roadmap defers "add no language". The ranking is also written for these three: test code, which separates P1 from P2 for a high or critical finding, is recognised by "pytest, Django and JavaScript naming" (README.md, "How triage works").

**Adding secrets scanning:** looking for credentials, keys and tokens in the scanned code.

Why not: ARCHITECTURE.md lists "secrets detection" as out of scope, and no roadmap step schedules it.

**Absorbing SCA:** triaging dependency vulnerabilities in this repository.

Why not: a companion project already does it. README.md calls sca-triage the "SCA companion", which "ranks npm dependency vulnerabilities P1–P3 the same way", and ARCHITECTURE.md lists "dependency analysis" as out of scope with a pointer to it.

## What this changes for Step 3

Step 3, "Become a triage platform (SARIF ingestion)", is the first step that builds on this framing. Its goal and its "Done when" line agree with the decision: "two scanners' SARIF (for example Semgrep and CodeQL) pass through one gate with new/pre-existing labels intact". This record changes no text in ROADMAP.md other than the Status of F-2.5.

| Item | Acceptance in ROADMAP.md | Does the framing support it as written? |
|---|---|---|
| F-3.1, "Parse SARIF into the shared finding model" | "Semgrep and CodeQL fixtures load into F-1.1 fields; malformed input yields no findings." | Yes. Imported SARIF 2.1.0 is in scope. See the note on malformed input below. |
| F-3.2, "Define explicit severity mappings for imported results" | "Equivalent high-severity Semgrep and CodeQL fixtures rank identically; unknown severities fail." | Yes. The same P1–P3 ranking is in scope. |
| F-3.3, "Carry diff-aware labels through imported findings" | "A finding absent from the base stays new despite a matching `partialFingerprint`." | Yes. The same new or pre-existing labels are in scope. The row does not say where the base's findings come from. |
| F-3.4, "Triage supplied Semgrep and CodeQL reports from the CLI" | "Import exits 1 for a new P1, 0 for a complete clean report, 2 for invalid input." | Yes, for the command line: the same gate and the same exit statuses. The in-scope list names three surfaces, and no Step 3 item brings imported reports to the GitHub Action or the GitHub App. |
| F-3.5, "Decide the finding datastore path before Phase 2" | "A decision record names one datastore path and defines stable finding identity." | Yes. The framing chooses no datastore and does not change this item. It does say which findings there are to identify: those of the Semgrep path and those of imported reports. |

What the framing fixes for these items:

- **Reports are supplied, not produced.** Step 3 reads reports that another tool wrote. Under the decision it adds no scanner that sast-triage runs.
- **Malformed input is not a clean result.** F-3.1's "malformed input yields no findings" is read together with F-3.4's exit status 2 for invalid input: the gate is the same one, and only a complete result can pass.
- **No new language is needed.** The Step 3 rows name two scanners, Semgrep and CodeQL, and no language, so they can be met with Python, JavaScript or TypeScript fixtures.

The Step 3 rows leave four questions open: where the base's findings come from for an imported report, what happens to a supplied report that holds a result in another language or of another kind, how far a supplied report is trusted, and imported reports in the GitHub Action and the GitHub App. They are listed in the next section and are not answered here. ROADMAP.md says the full text of each item arrives "by roadmap PR before a step becomes current", and that is where they belong.

## Not decided here / not authorized

Each of these needs a separate owner decision or approval. This record gives none of them.

- **Building Step 3:** F-3.1 to F-3.5 each keep their "Needs owner" mark in ROADMAP.md. Saying the framing supports an item does not approve building it.
- **The base side of an imported report:** on the Semgrep path sast-triage scans the base version of a changed file itself (README.md, "How triage works"). F-3.3 does not say where the base's findings come from when the report is supplied.
- **Imported results in another language or of another kind:** SARIF is a general format, so a supplied report can hold a result in a file of another language, or a result that is not a SAST finding, such as a secret or a vulnerable dependency. The decision puts new languages and secrets scanning out of scope for now and keeps SCA in sca-triage. What sast-triage does with a supplied report that holds such a result, for example refusing it with exit status 2, is not stated in the Step 3 rows and is not decided here.
- **Trust in an imported report:** who may produce the report and what is checked about it. A change to a trust boundary needs its own approval.
- **Imported reports in the GitHub Action and the GitHub App:** no roadmap item covers them.
- **Lifting an out-of-scope line:** adding a language, adding secrets scanning or moving SCA into this repository.
- **Native rule coverage:** the three rule candidates under "Native rule coverage" in ROADMAP.md stay deferred and "Needs owner". The existing Semgrep path is in scope; the decision neither schedules nor drops them.
- **Code, dependencies and the gate:** any change to code, to a dependency or a pinned version, to the gate's threshold (a new P1), to how P1, P2 and P3 are defined, or to exit statuses 0, 1 and 2.

## Existing statements that differ

The decision was compared with [README.md](../../README.md), [ARCHITECTURE.md](../../ARCHITECTURE.md) and [ROADMAP.md](../../ROADMAP.md) as they stood on 2026-11-12. This record changes none of them, apart from the Status of F-2.5 in ROADMAP.md. Three points differ, and each is a follow-up item for later work.

### 1. sast-triage described by its one scanner

- README.md, first sentence: "A Semgrep reviewer for Python, JavaScript and TypeScript, run from the command line, as a GitHub Action or as a GitHub App service."
- ARCHITECTURE.md, first paragraph: "sast-triage is a GitHub App service. It receives pull request webhooks, scans the changed Python, JavaScript and TypeScript files of the exact head commit with service-owned Semgrep rules".
- ROADMAP.md, title: "roadmap to an enterprise-grade SAST platform", which can be read as a scanner. Step 3's own heading, "Become a triage platform", matches the decision.

The first two describe today's code correctly: until Step 3 is built, Semgrep is the only source of findings. Under the decision they describe one in-scope path, not the product. The descriptions in `action.yml` and `pyproject.toml` repeat the README's in their own words.

### 2. "Many scanners and languages"

- ROADMAP.md, "Where it stands today", the "Scanner coverage" row: the enterprise bar is "Many scanners and languages via a common format". Under the decision, many scanners through SARIF is in scope and new languages are out of scope for now. The bar is a target and the decision is about now, so the two differ on languages until a later decision.
- ROADMAP.md, Step 3 goal: "Ingest SARIF 2.1.0 from any scanner". It agrees with "a triage and gate layer over any scanner". The decision's in-scope line is narrower than "any scanner": imported SAST results, with new languages and secrets scanning out of scope for now. The Step 3 rows do not say what happens to a result outside that line.

### 3. Statements that cover the Semgrep path only

- README.md, first section: "Rules, ignore files and `nosemgrep` comments from the scanned code are not used, and Semgrep never downloads rules."
- README.md, first section: "A Semgrep step in a repository's own CI reports every finding with the same urgency, and the pull request can edit that step."
- ARCHITECTURE.md, "Trust boundaries", "Pull request author": "Its Semgrep rules, ignore files, `.env`, Git metadata and `nosemgrep` comments never influence the scan."
- ARCHITECTURE.md, "Failure handling": "files Semgrep did not report as scanned fail the check; only a complete scan can pass".

All four stay true of the Semgrep path, which sast-triage runs itself. None of them covers an imported report, which another tool wrote with its own rules, ignore files and suppression comments, possibly in a CI step the pull request can edit. They are complete today and become incomplete once Step 3 is built. Two more statements are of the same kind: README.md, "Rules": "Rule severity ERROR is high and WARNING is medium.", which F-3.2 extends for imported results, and the "Scanner" line of ARCHITECTURE.md, "Security controls".

Nothing else that was checked disagrees with the decision: ARCHITECTURE.md, "Out of scope" already lists other languages, secrets detection and dependency analysis; README.md already points to sca-triage for SCA; ROADMAP.md calls sast-triage "a diff-aware SAST gate" and defers rule candidates that "add no language"; and the rule `js-hardcoded-session-secret` (README.md, "Rules"), which flags a literal session secret in code, is one of the 41 rules of the existing Semgrep path and already stands beside "secrets detection" being out of scope in ARCHITECTURE.md, so the decision changes nothing for it.
