### Changelog
All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.2] - 2026-11-11
### Fixed
- **`scan_repo.py --base ""` (or `--base=`) silently ran a full scan; an empty `--base` is now a usage error with exit status 2, and no result is issued.** For example, a CI job whose base variable is empty by mistake now stops with `--base needs a git ref; leave out --base for a full scan` instead of getting a full scan, which leaves out some folders that a `--base` scan covers. The GitHub Action is unchanged: it already leaves out `--base` when its `base` input is empty. [W-sast-triage-4]

## [2.1.1] - 2026-11-11
### Security
- **`scan_repo.py --base` and the GitHub Action skipped changed files in `build`, `dist`, `vendor` and `coverage` folders,** at any depth, without saying so, so a pull request that added `app/build/handler.py` with `os.system(request.args["c"])` passed the gate. The GitHub App scans those files. A `--base` scan now scans them too and skips only the folders the scanner refuses, `node_modules` and minified `*.min.js` files; the changed files it skips are listed in the output, under `skipped_changed_files` in the JSON and in the Markdown summary. A changed file there over 1 MiB now stops the scan with exit status 2, as in the App. Full scans skip the same folders as before.

### Fixed
- **A repeated GitHub Action invocation could append an earlier scan's summary after a scan error; it now issues no summary for that error.** For example, a clean scan followed by a missing-directory scan in the same job no longer repeats `Gate: PASS`; the second scan still exits with status 2. [W-sast-triage-12]
- A full scan skipped folders it could not read and could pass. It now stops with exit status 2 and issues no result.
- In local mode, a GitHub API rate limit during a scan left the Check in progress for good, because only durable mode retries. Local mode now completes it as failure ("Scan incomplete: GitHub API rate limit reached"), so it can be re-run.
- `deploy/validate_scanner.py`, the scanner check an operator runs against the production image, still checked only the 29 rules from before 2.1.0 while printing "all". It now has a sample for each of the 41 rules, checks the safe forms of the new ones, and fails if any rule in the rule file has no sample. A test runs it, so CI catches a rule added without one.

## [2.1.0] - 2026-11-10
### Added
- **Rules for request data reaching a dangerous call** (12 new rules, 41 in all: 21 Python, 20 JavaScript and TypeScript). Semgrep taint mode follows request data (Flask, Django and Express) within a function to SQL queries (`py-sql-injection`, `js-sql-injection`), file paths (`py-path-traversal`, `js-path-traversal`), outgoing requests (`py-ssrf`, `js-ssrf`) and HTML responses (`py-xss`, `js-xss`), all high severity. Numbers parsed from it, escaped or `basename`d values, records looked up with it, URLs with a fixed host, JSON responses and parameterized queries don't count. `py-sql-formatted-query` and `js-sql-formatted-query` (medium) flag a SQL query built by formatting any value, and `py-weak-password-hash` and `js-weak-password-hash` (high) flag md5 or sha1 applied to a password or secret. On OWASP NodeGoat the new rules add the server-side request forgery in `research.js` (7 P1 instead of 6), and on OWASP Juice Shop they find the SQL injections in `login.ts` and `search.ts` and the request forgery in the profile-image upload.

### Changed
- **Weak hashes are medium, not high.** `py-weak-md5`, `py-weak-sha1` and `js-weak-hash` are now WARNING, so an md5 cache key or ETag ranks P2 and no longer fails the gate. md5 or sha1 of a password or secret is the new high-severity rules' finding, and `hashlib.md5(..., usedforsecurity=False)` is not reported.
- When two rules report the same flaw (same file, line and CWE), only the most severe finding is kept.
- **The GitHub App downloads only the changed files.** It fetched the whole repository archive (capped at 25 MiB, so a larger repository failed every check) to scan a few files, and would have fetched it twice to scan the base versions. It now reads each changed Python, JavaScript and TypeScript file with the contents API, at the head commit and at the merge base, so repository size no longer matters and no archive is unpacked. A pull request with more than 500 such files fails closed.

### Security
- **A pull request could introduce a finding without failing the gate.** A finding counted as new only when one of its own lines changed, so editing the line above a call could make it dangerous while it stayed "pre-existing": changing `const cmd = 'ls -la'` to `'ls -la ' + req.query.dir` left the untouched `exec(cmd)` as `[P1, pre-existing]` and the gate passed. The base version of a changed file is now scanned too (the merge base, from git for `scan_repo.py --base` and from the GitHub API for the App), and a finding on untouched lines is pre-existing only if the base version has it, matched by rule and the text of the lines it covers. Only files with a finding on untouched lines need their base version: replaying OWASP NodeGoat's 78 merged pull requests, 25 needed a second Semgrep run and every result matched scanning all base versions. A base version that is missing, over 1 MiB or not scannable makes the file's findings new. Findings carry `new_because` and `fingerprint` in the JSON output.

### Changed
- `requirements.txt` pins `semgrep==1.79.0`, as `requirements-cli.txt` already did. It used to resolve to 1.79.0 only because newer Semgrep conflicts with FastAPI.

### Added
- Tests for four command-line paths of `scan_repo.py --base`: git missing or timing out, a changed file missing from the working tree, a rename without edits (and a change with no line diff, which counts as new), and the nothing-to-scan message. The suite has 172 tests.

## [2.0.0] - 2026-11-09
Upgrading from 1.0.0: the app reads `.env` only when `PRSEC_LOAD_DOTENV=1` (`make serve` sets it); the scanner accepts only one local rule file, so registry IDs, `auto` and URLs fail the scan; the demo and the `/docs`, `/redoc` and `/openapi.json` endpoints are removed.

### Added
- **Scan what changed (`scan_repo.py --base REF`).** Scans only the files changed since the merge base of `REF` and `HEAD`, and labels findings new or pre-existing from that diff with the same rules as a pull request, so the command line can gate a branch without the GitHub App. `--markdown FILE` also writes the summary.
- **GitHub Action (`action.yml`).** Runs `scan_repo.py` on pull requests against the base branch, fails the step on a new P1 and writes the job summary. CI runs it on the `make selfcheck` fixture.
- **`requirements-cli.txt`.** The scanner-only install (Semgrep 1.79.0 and certifi) for the command line and the Action.
- **JavaScript and TypeScript.** Pull requests that change `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts` or `.tsx` files are scanned with 14 new service-owned rules (29 in all) for Node and Express: `eval`, the `Function` constructor and string timers, `vm` with dynamic code, `child_process` `exec`/`execSync` with a built command, `node-serialize`, md5/sha1 hashes, `Math.random()` for secrets, disabled TLS verification, cookies without `httpOnly` or `secure`, disabled template autoescaping, MongoDB `$where` and queries taken from `req.*`, open redirects and hard-coded session secrets.
- Test code also follows JavaScript naming for JavaScript and TypeScript files: a `__tests__`, `spec`, `specs`, `e2e` or `cypress` folder, or a `*.test.*` or `*.spec.*` name. Python files are ranked as before.
- `scan_repo.py` scans a whole repository with the same rules, triage and gate, and prints the same report as the pull request summary (`--json` for machine-readable output). There is no diff, so every finding counts as new. It skips `.git`, `node_modules`, `vendor`, `dist`, `build`, `coverage`, virtualenv folders and `*.min.js` files, and exits 1 when the gate fails, 0 when it passes and 2 on a usage or scanner error.
- The README's example is now a full scan of OWASP NodeGoat at commit `c5cb68a`, with what the rules catch and miss there.
- Every service-owned rule, Python and JavaScript, has positive and negative examples in one live Semgrep scan (`tests/test_trusted_rules.py`), along with a real scan of a simulated pull request triaged against its diff.

### Security
- The scanner accepts exactly one local rule file, given by absolute path and outside the scanned tree. Registry IDs (`p/...`, `r/...`), `auto`, URLs, lists of configs and relative paths now fail the scan. Before, a missing config fell back to `SEMGREP_CONFIG` and then the `p/ci` registry pack, registry IDs and URLs were passed to Semgrep, and a relative path was resolved inside the scanned repository, so it could load rules the pull request wrote. Semgrep still runs with metrics and version checks off.
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
- `make check` runs the tests, then `make selfcheck`: a full-repository scan of a three-file fixture that must fail the gate on its planted P1. The suite has 168 tests.
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

## [0.1.2] - 2025-09-21
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

## [0.1.1] - 2025-09-21
### Added
- Repository foundations: `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- **Makefile** targets: `setup`, `lint`, `test`, `scan`, `protect`, `unprotect`, `release`.
- **Branch protection config** (`.github/branch-protection/protection.json`).
- **CODEOWNERS** for future review routing.

### Changed
- Enforced **admins included**, **no force pushes**, **no deletions** on `main`.

## [0.1.0] - 2025-09-21
### Added
- Initial tag and first protected merge baseline.
