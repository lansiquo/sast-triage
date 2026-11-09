# sast-triage

A Semgrep reviewer for Python, JavaScript and TypeScript, run from the command line, as a GitHub Action
or as a GitHub App service. It labels each finding **new** or **pre-existing** from the diff, ranks it
**P1–P3**, and fails only on new P1 findings, so a pull request is blocked by what it introduced, not by
what was already there.

A Semgrep step in a repository's own CI reports every finding with the same urgency, and the pull request
can edit that step. `sast-triage` runs 29 service-owned rules for high-signal patterns (`.py`, `.js`,
`.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`). Rules, ignore files and `nosemgrep` comments from the scanned code
are not used, and Semgrep never downloads rules. Findings are review aids, not a security audit. Its SCA
companion, [sca-triage](https://github.com/lansiquo/sca-triage), ranks npm dependency vulnerabilities
P1–P3 the same way.

## Example: OWASP NodeGoat

I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Express and
MongoDB app for learning the OWASP Top 10. The results below are from its latest commit, `c5cb68a`
(June 2023). It needs Python 3.11–3.14. The scan only parses its source; none of NodeGoat's code is
installed or run. From an empty folder:

```bash
git clone https://github.com/lansiquo/sast-triage.git
python3 -m venv sast-venv
sast-venv/bin/pip install -r sast-triage/requirements-cli.txt
git clone https://github.com/OWASP/NodeGoat.git
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat                   # whole project
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat --base 5e71697~1  # last two PRs
```

The whole-project scan, without the closing legend and with the gate's repeat of the six P1 lines
shortened:

```text
sast-triage full scan of NodeGoat
Full scan: every finding counts as new (there is no diff).
44 Python, JavaScript and TypeScript files, 29 service-owned rules.
Skipped: .git, node_modules, vendor, dist, build, coverage, .hg, .svn, .venv, venv, __pycache__ folders and minified *.min.js files.

Full scan (44 files): FAILURE
  [P1, new] Gruntfile.js:165  js-child-process-exec
  [P1, new] app/data/allocations-dao.js:78  js-nosql-injection
  [P1, new] app/routes/contributions.js:32  js-dangerous-eval
  [P1, new] app/routes/contributions.js:33  js-dangerous-eval
  [P1, new] app/routes/contributions.js:34  js-dangerous-eval
  [P1, new] config/env/all.js:8  js-hardcoded-session-secret
  [P2, new] app/routes/index.js:72  js-open-redirect
  [P2, new] server.js:78  js-cookie-without-secure
  [P2, new] server.js:137  js-template-autoescape-disabled
### sast-triage — Semgrep summary

**Gate: FAIL** — 6 new P1 findings:
- … (the six P1 findings above)

| Priority | New | Pre-existing |
|---|---|---|
| P1 | 6 | 0 |
| P2 | 3 | 0 |
| P3 | 0 | 0 |
```

**Caught**, by NodeGoat's own lesson numbers (OWASP Top 10 2013):

- **Server-side JavaScript injection (A1):** `contributions.js` passes three form fields to `eval()`.
- **NoSQL injection (A1):** `allocations-dao.js` builds a MongoDB `$where` from the `threshold` query parameter.
- **Session management (A2):** the session secret is hard-coded (`cookieSecret` in `config/env/all.js`),
  and `server.js` configures `express-session` without `cookie.secure`.
- **Cross-site scripting (A3):** `server.js` turns off Swig's autoescaping for every template.
- **Open redirect (A10):** `/learn` redirects to `req.query.url`.

`Gruntfile.js:165` is not one of the lessons: the `db-reset` build task runs a shell command built from
`NODE_ENV` and a task argument. It is a real injection sink, but only whoever runs Grunt controls it.

**Missed:** log injection (A1), plain-text passwords (A2), insecure direct object references (A4), missing
security headers (A5), plain HTTP (A6), missing access control on `/benefits` (A7), CSRF (A8), vulnerable
dependencies (A9, see [sca-triage](https://github.com/lansiquo/sca-triage)), server-side request forgery in
`research.js` and a ReDoS-prone regex in `profile.js`. No rule covers them, HTML templates are not scanned,
and a request value passed to another module before it reaches a query is not traced.

`--base 5e71697~1` reviews NodeGoat's last two pull requests the way the gate reviews a pull request.
[#233](https://github.com/OWASP/NodeGoat/pull/233) moved the tutorial routes out of `app/routes/index.js`
into a new `tutorial.js`, and #290 only edited an HTML view. The output, without the legend:

```text
sast-triage scan of NodeGoat, changes since 5e71697~1
A finding is new when it covers a line changed since the base; only a new P1 fails.
2 changed Python, JavaScript and TypeScript files, 29 service-owned rules.
Skipped: .git, node_modules, vendor, dist, build, coverage, .hg, .svn, .venv, venv, __pycache__ folders and minified *.min.js files.

Changes since 5e71697~1 (2 files): SUCCESS
  [P2, pre-existing] app/routes/index.js:72  js-open-redirect
### sast-triage — Semgrep summary

**Gate: PASS** — no new P1 findings. Anything else is annotated but doesn't fail the check.

| Priority | New | Pre-existing |
|---|---|---|
| P1 | 0 | 0 |
| P2 | 0 | 1 |
| P3 | 0 | 0 |
```

The open redirect is in a file #233 changed, but not on a line it changed, so it is pre-existing. The other
eight findings are in files neither pull request touched, so they are not scanned, and the gate passes. The
[case study](https://dotrobin.dev/sast-triage.html) shows both runs.

## Use it on your project

Requires Python 3.11–3.14. A scan reads source files only: nothing is run or installed, and it needs no
GitHub account, token or network. `requirements-cli.txt` installs only Semgrep, pinned to the tested
1.79.0; set `SEMGREP_BIN` to use another.

```bash
git clone https://github.com/lansiquo/sast-triage.git
python3 -m venv sast-venv
sast-venv/bin/pip install -r sast-triage/requirements-cli.txt
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project --base origin/main
```

```text
scan_repo.py DIRECTORY [--base REF] [--json] [--markdown FILE] [--timeout SECONDS]
```

Without `--base`, every supported file is scanned and every finding counts as new, so on an existing
codebase findings that were already there count too. With `--base REF`, only the files changed since the
merge base of `REF` and `HEAD` are scanned, and a finding is new when it covers a line they added or
changed: the same labels a pull request gets. `--json` prints the result as JSON, `--markdown FILE` also
writes the Markdown summary, and `--timeout` limits the scan (default 300 seconds).

Files in `.git`, `node_modules`, `vendor`, `dist`, `build`, `coverage` and virtualenv folders, and minified
`*.min.js` files, are skipped. The project's own Semgrep rules, ignore files and git diff helpers are not used.

## GitHub Action

In a workflow that runs on `pull_request`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0               # the base branch's history, to diff against it
- uses: lansiquo/sast-triage@v2.0.0
  with:
    path: .                      # directory to scan
    base: ""                     # default: the pull request's base branch; "none" for a full scan
```

Both inputs are optional (defaults shown). On a pull request it scans the files changed since the base
branch; on other events, or with `base: none`, it scans everything. The step fails when the gate fails and
adds the summary to the job summary. It installs only `requirements-cli.txt` with the runner's Python and
uses no other actions. Pin a release tag such as `@v2.0.0`, or a full commit SHA for the strictest
supply-chain safety.

## How triage works

| | Meaning | When new |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the gate |
| **P2** | High or critical in test code, or medium in runtime code | Reported; a warning on the Check Run |
| **P3** | Everything else | Reported; a notice on the Check Run |

**New or pre-existing.** A finding is new if it covers a line the pull request (or, from the command line,
the changes since `--base`) added or changed. Pre-existing findings are still reported, as notices.

- No diff for a file (too large or unreadable): every finding in it counts as new.
- Renamed with no changes: unchanged.
- Renamed or copied from test code to runtime code: every finding counts as new, since its priority went up.

**Test code** follows pytest, Django and JavaScript naming: a `test` or `tests` folder or a `test_*` name;
for Python also `*_test.py` or `tests.py`; for JavaScript and TypeScript also a `__tests__`, `spec`,
`specs`, `e2e` or `cypress` folder, or a `*.test.*` or `*.spec.*` name. `conftest.py` always counts as
runtime code. A rule that rates its own confidence or likelihood `LOW` drops one level.

**Gate.** It fails only when a finding is both new and P1. Scanner errors and partial results also fail it;
only a complete scan can pass.

## Rules

`trusted_rules.py` holds all 29 service-owned rules. Rule severity ERROR is high and WARNING is medium.

**Python (15):** `hashlib.md5` and `sha1`; `yaml.load` without a safe loader, `yaml.unsafe_load`,
`pickle.load` and `pickle.loads`; `os.system`, `os.popen` and `subprocess` with `shell=True`; `eval` and
`exec`; `requests` with `verify=False`; the `random` module; `tempfile.mktemp`; `tarfile.extractall`.

**JavaScript and TypeScript (14):**

| Rule | Severity | CWE | Flags |
|---|---|---|---|
| `js-dangerous-eval` | high | 95 | `eval()` of anything but a string literal |
| `js-implied-eval` | high | 95 | `Function` with a non-literal body; `setTimeout` or `setInterval` with a string built at runtime |
| `js-vm-dynamic-code` | high | 95 | `vm.runInContext`, `runInNewContext`, `runInThisContext`, `compileFunction` or `new vm.Script` with non-literal code |
| `js-child-process-exec` | high | 78 | `child_process` `exec` or `execSync` with a non-literal command |
| `js-insecure-deserialization-node-serialize` | high | 502 | `node-serialize` `unserialize()` |
| `js-weak-hash` | high | 327 | `createHash('md5')` or `createHash('sha1')` |
| `js-math-random-for-secrets` | medium | 338 | `Math.random()` stored as a token, secret, password, salt, nonce, OTP or similar |
| `js-tls-verification-disabled` | high | 295 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = '0'` |
| `js-cookie-without-httponly` | medium | 1004 | `httpOnly: false` |
| `js-cookie-without-secure` | medium | 614 | `secure: false` on a cookie; inline `express-session` options without `cookie.secure` |
| `js-template-autoescape-disabled` | medium | 79 | `autoescape: false` (Swig, Nunjucks), Handlebars `noEscape: true` |
| `js-nosql-injection` | high | 943 | a MongoDB `$where` that is not a literal; a query, or a query field, taken straight from `req.body`, `req.query` or `req.cookies` |
| `js-open-redirect` | medium | 601 | `res.redirect()` to a target that starts with `req.query`, `req.params`, `req.body` or `req.param()` |
| `js-hardcoded-session-secret` | high | 798 | a literal secret for `express-session`, `cookie-session` or `cookieParser`, or a literal `cookieSecret` or `sessionSecret` |

## Review pull requests with a GitHub App

The webhook service scans each pull request's head commit and reports the result as a Check Run, with up
to 200 annotations, P1 first. It needs the full `requirements.txt`, which pins Semgrep 1.79.0:
newer Semgrep pins `opentelemetry-api` below the version current FastAPI needs, and forcing it would also
pull in `mcp` and `opentelemetry-api` releases with known advisories.

```bash
git clone https://github.com/lansiquo/sast-triage.git
cd sast-triage
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # set GITHUB_WEBHOOK_SECRET, GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_PATH
make serve             # http://127.0.0.1:8000, liveness at /health
```

The app reads `.env` only when `PRSEC_LOAD_DOTENV=1`, which `make serve` sets. Otherwise it takes
configuration from the environment. Register your own GitHub App with **pull request** events and Contents
read, Pull requests read and Checks write. A real webhook creates real Check Runs, so use a test repository.

> **Changed since v1.0.0:** the app reads `.env` only when `PRSEC_LOAD_DOTENV=1`, and the scanner
> accepts only its own local rule file, so Semgrep registry IDs, `auto` and URLs fail the scan.

This local mode scans in the web process, two at a time. The durable mode (SQLite queue, separate worker,
rootless Docker sandbox) is prepared but not live; see [deploy/README.md](deploy/README.md).

## Exit codes

| Code | `scan_repo.py` and the GitHub Action |
|---|---|
| 0 | The gate passes: no new P1 finding, or nothing to scan |
| 1 | The gate fails: at least one new P1 finding |
| 2 | Usage, git or scanner error, such as a missing directory, an unknown `--base` ref, a file over 1 MiB or an incomplete scan; no result is issued |

## Scope and limits

- **Rules match within one file.** A value that passes through another function or module before it
  reaches a dangerous call is not traced.
- **Pre-existing means untouched, not unrelated.** A change elsewhere (for example, a new import) can make
  an untouched line match; that finding stays pre-existing and doesn't fail the gate.
- **Size limits fail closed:** 1 MiB per scanned file; for the GitHub App also a 1 MiB webhook body,
  25 MiB archive, 100 MiB extracted, 10,000 archive members and 3,000 changed files.
- **Local mode is not an OS sandbox.** It strips credentials from the scanner and stages only the selected
  files. Before scanning untrusted public repositories, use the durable mode's isolated worker.

## More

- [ARCHITECTURE.md](ARCHITECTURE.md): components, execution modes, failure handling and security controls, with a diagram
- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, tests and repository layout
- [Case study](https://dotrobin.dev/sast-triage.html): design and runs on OWASP NodeGoat
