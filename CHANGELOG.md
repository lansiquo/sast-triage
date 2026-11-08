### Changelog
All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Security
- The diff reader splits a patch on `\n` only. It used `str.splitlines()`, which also breaks on form feeds, U+2028 and other characters that are legal in Python comments, so a pull request could shift the recorded line numbers and get a new P1 finding labelled pre-existing. Each hunk must also hold exactly the old and new line counts its header declares; any mismatch makes the file's changes unknown, so every finding in it counts as new.

### Changed
- The demo now simulates one pull request across a runtime file and a test file, with five findings that cover every triage outcome: P1 new (fails), P1 pre-existing, P2 from medium severity in runtime code, P2 from high severity in test code, and P3 pre-existing.

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
- **Branch protection config** (`.github/branch-protection/protection.json`) and `make protect` to apply it.
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

#### I came through a merge