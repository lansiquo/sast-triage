### Changelog
All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- **JavaScript and TypeScript.** Pull requests that change `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts` or `.tsx` files are scanned with 14 new service-owned rules (29 in all) for Node and Express: `eval`, the `Function` constructor and string timers, `vm` with dynamic code, `child_process` `exec`/`execSync` with a built command, `node-serialize`, md5/sha1 hashes, `Math.random()` for secrets, disabled TLS verification, cookies without `httpOnly` or `secure`, disabled template autoescaping, MongoDB `$where` and queries taken from `req.*`, open redirects and hard-coded session secrets.
- Test code also follows JavaScript naming for JavaScript and TypeScript files: a `__tests__`, `spec`, `specs`, `e2e` or `cypress` folder, or a `*.test.*` or `*.spec.*` name. Python files are ranked as before.
- `scan_repo.py` scans a whole repository with the same rules, triage and gate, and prints the same report as the pull request summary (`--json` for machine-readable output). There is no diff, so every finding counts as new. It skips `.git`, `node_modules`, `vendor`, `dist`, `build`, `coverage`, virtualenv folders and `*.min.js` files, and exits 1 when the gate fails, 0 when it passes and 2 on a usage or scanner error.
- The README's example is now a full scan of OWASP NodeGoat at commit `c5cb68a`, with what the rules catch and miss there.
- Every service-owned rule, Python and JavaScript, has positive and negative examples in one live Semgrep scan (`tests/test_trusted_rules.py`), along with a real scan of a simulated pull request triaged against its diff.

### Security
- The diff reader splits a patch on `\n` only. It used `str.splitlines()`, which also breaks on form feeds, U+2028 and other characters that are legal in Python comments, so a pull request could shift the recorded line numbers and get a new P1 finding labelled pre-existing. Each hunk must also hold exactly the old and new line counts its header declares; any mismatch makes the file's changes unknown, so every finding in it counts as new.
- A file moved from test code to runtime code counts as entirely new, with or without edits. A pure rename used to make every finding in it pre-existing, so moving high-severity code out of `tests/` raised it to P1 without failing the check.
- `conftest.py` is ranked as runtime code, even inside a `tests` folder. pytest imports it on every run, so high-severity findings in it are P1, not P2.

### Fixed
- A changed file in a `test`, `tests`, `vendor`, `build`, `dist` or `node_modules` folder failed the scan as incomplete. With no `.semgrepignore` in the staged copy, Semgrep fell back to built-in ignore defaults and skipped those folders. The runner now writes an empty, service-owned `.semgrepignore` so every staged file is scanned.
- CI runs `make check` on Python 3.11, 3.12, 3.13 and 3.14 (it ran 3.12 only). The README explains why the development environment resolves to Semgrep 1.79.0.
- `rules/security.yaml` loads in Semgrep. Several patterns needed quoting, the `dangerouslySetInnerHTML` pattern was invalid JSX, and the unpinned-actions rule could never match; it now flags remote actions whose ref is not a full commit SHA. A test scans each rule pack in `rules/`.
- Durable mode: a permanent GitHub error during a scan (HTTP 400, 401, 403, 404, 405, 410 or 422) now completes the Check Run as failure, with the status in its summary. It used to leave the Check in progress forever while the job was marked failed.
- The pull request's head commit is downloaded from the base repository, which holds every PR head commit. Downloading it from a fork failed for private or deleted forks, because durable mode scopes the installation token to the base repository.

### Changed
- Branch protection lives in `docs/branch-protection/`: `protection.json` and a README with the `gh api` command that applies it. The required check is now `PRSecurityScan`, the App's default Check Run name, and the review settings are nested under `required_pull_request_reviews`; they were top-level keys next to a null value, so applying the old file would have turned off required reviews. The workflow, CODEOWNERS and pull request templates under `.github/branch-protect/` and `.github/branch-protection/` are removed: GitHub never ran them, the workflow used actions pinned to tags rather than commit SHAs, and they named a check (`RobinSec`) that nothing reports. The 1.0.0 notes no longer mention `make protect`, which that release did not include.
- The webhook app loads `.env` only when `PRSEC_LOAD_DOTENV=1`. `make serve` sets it, so the documented local flow is unchanged; starting the app any other way no longer reads a `.env` from the working directory. Durable deployments already set `PRSEC_LOAD_DOTENV=0`.
- The webhook app no longer serves `/docs`, `/redoc` or `/openapi.json`.
- `make check` runs the tests, then `make selfcheck`: a full-repository scan of a three-file fixture that must fail the gate on its planted P1. The suite has 159 tests.
- An earlier cut took the test suite from 286 tests to 159, and line and branch coverage of the service code rose from 86% to 95%. Table tests now run their cases in a loop inside one test; no case was dropped. New tests cover fail-closed paths that had none: scan-slot release when setup fails, scope and queue-full responses, readiness, token and App key handling, archive and file-list limits, scanner configuration and output checks, the Docker sandbox preflight, worker scope, and the queue and deployment check tools.

### Removed
- The intentionally vulnerable demo material and its tooling: `demo.py` and `make demo`, the local interactive showcase (`demo_web.py`, `demo_rules.py`, `demo/` with its fixtures, showcase examples and UI), the behavioral lab (`demo_behavior.py`, `demo/behavior_worker.py`), their docs (`deploy/local-showcase.md`, `deploy/behavioral-lab.md`) and their tests, including the Playwright browser check. What those tests covered outside the demo moved into the remaining suite: rule examples, the ignored `nosemgrep` comment and a real scan triaged against a diff.

## [1.0.0] - 2026-11-05
### Added
- **Triage.** Each finding is labelled **new** or **pre-existing** from the pull request's diff and ranked **P1/P2/P3** by severity and runtime vs test code, like sca-triage. A rule that rates its own confidence or likelihood LOW drops one level.
- Annotation titles start with the priority and status, e.g. `[P1, new]`, and findings are sorted P1 first before the 200-annotation cap.
- The demo simulates a pull request so both labels show.
- **CI.** GitHub Actions runs `make check` on every pull request and every push to main, with both actions pinned to full commit SHAs.

### Changed
- Renamed the project to **sast-triage**, the SAST companion to sca-triage.
- The Check Run fails only on new P1 findings; it used to fail on any finding. Annotation colour follows the same rule, and the summary shows the gate result and a priority × new/pre-existing table instead of severity counts.
- README now states what works today, including the triage, and what isn't built yet (deployment).
- The deployment docs, the example environment and the README name the renamed repositories, `lansiquo/sast-triage` and `lansiquo/sca-triage`.

### Removed
- Tracked `.DS_Store` and `__pycache__` files, which `.gitignore` already covers.

## [v0.1.0] - 2025-09-21
### Added
- Initial tag and first protected merge baseline.

## [v0.1.1] - 2025-09-21
### Added
- Repository foundations: `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- **Makefile** targets: `setup`, `lint`, `test`, `scan`, `protect`, `unprotect`, `release`.
- **Branch protection config** (`.github/branch-protection/protection.json`).
- **CODEOWNERS** for future review routing.

### Changed
- Enforced **admins included**, **no force pushes**, **no deletions** on `main`.


## [v0.1.2] - 2025-09-21
### Added
- **CI security gate**: GitHub Actions workflow **RobinSec / RobinSec** using `semgrep ci` (PR-aware), with
  explicit permissions, concurrency cancel, job timeout, and SARIF upload to the Security tab.
- **Semgrep ruleset**: initial custom rules (`py.dangerous.eval`, `py.subprocess.shell-true`, plus
  org rules like `py.yaml.unsafe-load` and `py.crypto.weak-random`), alongside curated packs
  (`p/security-audit`, `p/secrets`).
- **.semgrepignore** to skip `node_modules/`, `dist/`, `venv/`, and other noise.
- **PR template** with a minimal security checklist.

### Changed
- **Branch protection** now requires the single check **“RobinSec / RobinSec”** (removed the old
  `pr-security-review / semgrep` requirement to avoid duplicate/ghost checks).
- Tuned protection for **strict status checks**, **linear history**, and **conversation resolution**.

### Fixed
- Resolved hanging checks by aligning the required context to the workflow/job name and ensuring the
  job always completes (timeouts + `semgrep ci`).
