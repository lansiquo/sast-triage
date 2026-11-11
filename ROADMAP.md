# Roadmap

Owner-approved order of work for sast-triage. Items are built one at a time, lowest step first.
Status changes only through merged pull requests.

## Step 1: Clearer results from the command line

Goal: Users can write results as SARIF, give the Action's scan more time, and fix a failed `--base` diff from the error message alone.

### F-1.1 SARIF output from the command line (`--sarif FILE`)
- Status: planned
- Why: README "Use it on your project" lists only the console report, `--json` and `--markdown`, and README "GitHub Action" only writes the job summary, so findings can't reach GitHub code scanning or other SARIF tools. CHANGELOG 0.1.2 had a SARIF upload to the Security tab; it went away with the RobinSec workflow removed in 2.0.0.
- Acceptance:
  - `scan_repo.py DIR --sarif FILE` writes a SARIF 2.1.0 JSON file (`"version": "2.1.0"`) with one run, `tool.driver.name` `sast-triage`, each reported rule ID once in `tool.driver.rules`, and one result per finding in the `--json` output for the same input, in the same order.
  - Each result carries `ruleId`, the relative path with forward slashes as `locations[0].physicalLocation.artifactLocation.uri`, `region.startLine` and `region.endLine`, the finding's `fingerprint` under `partialFingerprints`, and `properties` with `priority`, `new`, `new_because` and `cwe` equal to the finding's `--json` fields.
  - Each result's `level` follows the Check Run annotation levels: `error` for a new P1, `warning` for a new P2, `note` otherwise.
  - With `--base REF`, `properties.new` is false for a pre-existing finding and true for a new one, matching `--json` for the same run.
  - With nothing to scan, the command exits 0 and FILE holds one run with no results.
  - On a scanner error, a git error or a file over 1 MiB, the command exits 2, FILE is not created, and an existing FILE is left unchanged.
  - Adding `--sarif` does not change the exit status, the console report, the `--json` output or the `--markdown` file for the same input.
- Out of scope: uploading SARIF; an Action input (F-2.2); new fields in `--json`.
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
- Out of scope: the GitHub App's scan timeout; changing which values `--timeout` accepts; the Action's install step and permissions.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

## Step 2: The Action reports like the App

Goal: Action users see each finding as an annotation on the pull request and can hand a SARIF file to code scanning, while the Action still uses no token.

### F-2.1 Pull request annotations from the command line and the Action
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
- Out of scope: creating Check Runs from the Action (it uses no token); changing the App's annotations.
- Touches: scan_repo.py, analyzers/semgrep_runner.py (sharing the annotation levels only), action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: M

### F-2.2 Action input that writes SARIF
- Status: planned
- Why: After F-1.1 the command line writes SARIF, but the Action can't ask for it. SECURITY.md says the Action uses no token and README "GitHub Action" says it uses no other actions, so a user's own workflow step has to do the upload.
- Acceptance:
  - `action.yml` has an optional `sarif` input, default `""`; when set, the Scan step passes `--sarif` with that path; when empty, the arguments are unchanged. The input reaches the script only through an environment variable.
  - When the scan exits 2, no file is created at that path, so a later upload step has nothing to upload.
  - README "GitHub Action" shows a separate upload step in the user's workflow, pinned to a full commit SHA, notes that the step needs `security-events: write`, and states that sast-triage itself still uses no token and no other actions.
- Out of scope: uploading from the Action (F-4.2); any permission of the Action.
- Touches: action.yml, tests/test_scan_repo.py, README.md, CHANGELOG.md
- Size: S

## Step 3: More flaws found in the same languages

Goal: The service-owned rules find log injection, regular expressions prone to catastrophic backtracking and FastAPI request data, with no change to how findings are ranked or gated.

### F-3.1 Log injection rules (`py-log-injection`, `js-log-injection`)
- Status: planned
- Why: README "Example: OWASP NodeGoat" lists log injection (A1) under "Missed", and none of the 41 rules in `trusted_rules.py` has a logging sink.
- Acceptance:
  - Two new rules, `py-log-injection` and `js-log-injection`: severity WARNING (medium), CWE-117, Semgrep taint mode within one function, with the same request-data sources as the existing request-data rules.
  - Positive examples flagged in a live Semgrep 1.79.0 scan in `tests/test_trusted_rules.py`: Flask request data passed to `logging.info`, `logger.warning` or `app.logger.error`; Express request data passed to `console.log` or `console.error`, also as a later argument (`console.log('login failed for', req.body.user)`).
  - Negative examples not flagged: a literal message; a value passed through `int()` or `parseInt()`; a value with line breaks removed (`.replace('\n', '')` in Python, `.replace(/[\r\n]/g, '')` in JavaScript); a value passed through `json.dumps` or `JSON.stringify`.
  - `deploy/validate_scanner.py` has a sample for each new rule, and its test passes.
  - Rule counts are updated everywhere they appear (README.md, ARCHITECTURE.md, CONTRIBUTING.md, trusted_rules.py), and README "Rules" lists both rules.
  - `make selfcheck` behaves as before: its planted P1 fails the gate.
  - README's NodeGoat "Missed" paragraph no longer lists log injection without saying that a rule now covers it and that the example output predates the rule.
- Out of scope: data flow across functions or files; logging libraries other than Python's `logging` and `console`; re-running the NodeGoat example.
- Touches: trusted_rules.py, tests/test_trusted_rules.py, deploy/validate_scanner.py, README.md, ARCHITECTURE.md, CONTRIBUTING.md, CHANGELOG.md
- Size: M

### F-3.2 Rules for regular expressions with nested quantifiers
- Status: planned
- Why: README "Example: OWASP NodeGoat" lists "a ReDoS-prone regex in `profile.js`" under "Missed", and no rule in `trusted_rules.py` looks at regular expressions.
- Acceptance:
  - Two new rules, `py-regex-nested-quantifier` and `js-regex-nested-quantifier`: severity WARNING (medium), CWE-1333. They flag a literal pattern in which a group that ends in `+` or `*` is itself repeated with `+`, `*` or `{n,}`, such as `([0-9]+)+`, `(a*)*` or `(\d+)*`.
  - Positive examples flagged in a live Semgrep 1.79.0 scan: a JavaScript regex literal (`/([0-9]+)+#/`), `new RegExp('(a+)+$')`, and Python `re.compile`, `re.match` and `re.search` with such a pattern.
  - Negative examples not flagged: `([0-9]+)`, `[0-9]+`, `(?:ab)+`, `(a|b)+`, a pattern built at runtime, and a string literal with such text that is not used as a pattern.
  - `deploy/validate_scanner.py` has a sample for each new rule, and its test passes.
  - Rule counts are updated everywhere they appear, and README "Rules" lists both rules.
  - `make selfcheck` behaves as before: its planted P1 fails the gate.
  - README's NodeGoat "Missed" paragraph no longer lists the ReDoS-prone regex without saying that a rule now covers it and that the example output predates the rule.
- Out of scope: deciding in general whether a pattern backtracks badly; patterns built at runtime; request data used as a pattern.
- Touches: trusted_rules.py, tests/test_trusted_rules.py, deploy/validate_scanner.py, README.md, ARCHITECTURE.md, CONTRIBUTING.md, CHANGELOG.md
- Size: M

### F-3.3 FastAPI and Starlette query and path parameters as request data
- Status: planned
- Why: README "Rules" names Flask and Django request data as the Python sources, and the source pattern in `trusted_rules.py` accepts only `request.args`, `form`, `values`, `json`, `cookies`, `headers`, `data`, `files`, `view_args` and the Django names. A FastAPI or Starlette `request.query_params` or `request.path_params` is not followed, though sast-triage's own service (`app.py`) is a FastAPI app.
- Acceptance:
  - `py-sql-injection`, `py-path-traversal` and `py-ssrf` also treat `request.query_params` and `request.path_params` as request data.
  - Positive examples flagged in a live Semgrep 1.79.0 scan: one FastAPI handler per rule, such as `request.query_params["q"]` formatted into `cursor.execute(...)`.
  - Negative examples not flagged: the same handlers with `int()`, a parameterized query, `secure_filename` and a URL with a fixed `https://host/` prefix.
  - Existing positive and negative examples for the three rules give the same results.
  - `deploy/validate_scanner.py` passes, and README "Rules" names FastAPI and Starlette.
  - `make selfcheck` behaves as before: its planted P1 fails the gate.
- Out of scope: `py-xss` (a FastAPI route returns JSON by default, so its return value is not an HTML response); FastAPI's typed handler parameters (`q: str = Query(...)`); new rules.
- Touches: trusted_rules.py, tests/test_trusted_rules.py, deploy/validate_scanner.py, README.md, CHANGELOG.md
- Size: S

## Step 4: Owner decisions on the gate and code scanning

Goal: If Robin approves each item, teams can block merges on new P2 findings, and the Action can send its SARIF to code scanning without a separate step.

### F-4.1 Opt-in gate on new P2 findings
- Status: planned
- Needs owner: Should a stricter gate exist? Choose one: (a) no, the gate stays "new P1 only" everywhere; (b) yes, for the command line and the Action only (`--fail-on P2` and a `fail-on` input), documented as a deliberate difference from the App; (c) yes, for the App too, through a service setting. The acceptance below is for option (b); option (c) adds the App and its tests.
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

### F-4.2 Upload SARIF to code scanning from the Action
- Status: planned
- Needs owner: Should the Action upload SARIF itself? Choose one: (a) no, the Action stays tokenless and users upload with their own step (F-2.2); (b) yes, through a `github-token` input and the code scanning API, which needs `security-events: write` in the user's workflow and changes SECURITY.md's statement that the Action uses no token (an edit only Robin makes). The acceptance below is for option (b).
- Why: SECURITY.md "Command line and GitHub Action" says the Action uses no token, and README "GitHub Action" says it uses no other actions. Uploading needs a token with `security-events: write`, which changes the Action's trust boundary, so it needs Robin.
- Acceptance:
  - With `upload-sarif: "true"` and a `github-token`, the Action uploads the F-2.2 SARIF file once, after a complete scan, for the workflow's commit and ref; a mocked API test checks the request.
  - A scan that exits 2 uploads nothing.
  - The token reaches the step only through an environment variable, never appears in output, and is not in the scanner's environment: the runner's environment allowlist is unchanged.
  - An upload error makes the step fail, so a failed upload never looks like a passing check.
  - Without the input, the Action uses no token, as today.
- Out of scope: uploading from the command line or the App; any other use of the token.
- Touches: action.yml, scan_repo.py or a new upload helper, tests, README.md, CHANGELOG.md; SECURITY.md by Robin
- Size: M
