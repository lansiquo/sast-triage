# sast-triage

sast-triage runs Semgrep on Python, JavaScript and TypeScript code. For a pull request it labels each
finding **new** or **pre-existing**, ranks it **P1–P3**, and fails the check only on new P1 findings, so a
pull request is blocked by what it introduced, not by what was already there.

It runs 41 service-owned rules for high-signal patterns (`.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`,
`.tsx`). Rules, ignore files and `nosemgrep` comments from the scanned code are not used, and Semgrep never
downloads rules. A scan reads source files only: nothing in the project is run or installed. Findings are
review aids, not a security audit. Its SCA companion,
[sca-triage](https://github.com/lansiquo/sca-triage), ranks npm dependency vulnerabilities P1–P3 the same
way.

## Quick start

There are three ways to run the same scan: the [GitHub Action](#github-action) in CI, the
[command line](#command-line), or the command line
[installed as a package](#install-as-a-package-local-build). A
[GitHub App](#review-pull-requests-with-a-github-app) service can report the result as a Check Run
instead.

## GitHub Action

In a workflow that runs on `pull_request`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0               # the base branch's history, to diff against it
- uses: lansiquo/sast-triage@v2.6.2
  with:
    path: .                      # directory to scan
    base: ""                     # default: the pull request's base branch; "none" for a full scan
    timeout: ""                  # scanner time limit in seconds; default: 300
    sarif: ""                    # also write the findings to this SARIF file; default: no file
    annotations: "false"         # "true": also annotate the findings on the pull request
```

All five inputs are optional (defaults shown):

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan |
| `base` | `""` | Git ref to compare with. Empty: the pull request's base branch, or a full scan on other events. `none`: always a full scan |
| `timeout` | `""` | Scanner time limit in seconds, passed as `--timeout`. Empty: the default of 300 seconds |
| `sarif` | `""` | File to also write the findings to, passed as `--sarif`. A relative path is relative to the workspace. Empty: no SARIF file |
| `annotations` | `"false"` | `"true"` adds `--github-annotations`. Any value other than `"true"` or `"false"`, an empty one included, stops the step with exit status 2 before the scan |

The step fails when the gate fails and adds the summary to the job summary. It installs only
`requirements-cli.txt` with the runner's Python, and it uses no token and no other actions. Pin a release
tag such as `@v2.6.2`, or a full commit SHA for the strictest supply-chain safety. A pull request that can
edit the workflow can edit this step too; the
[GitHub App](#review-pull-requests-with-a-github-app) runs outside the repository's workflows.

Annotations need no added permission. The Action does not upload the SARIF file: to show the findings in
GitHub code scanning, upload it in a separate step of your own workflow, pinned to a full commit SHA, in a
job that has `security-events: write`:

```yaml
on: pull_request
jobs:
  sast-triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read               # the checkout
      security-events: write       # the upload step
      actions: read                # the upload step, only needed in a private repository
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: rm -rf sast-triage.sarif          # anything already at the path is not this scan's result
      - id: scan
        uses: lansiquo/sast-triage@v2.6.2
        with:
          sarif: sast-triage.sarif
      - if: ${{ !cancelled() && steps.scan.outcome != 'skipped' && hashFiles('sast-triage.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066   # v4.39.3
        with:
          sarif_file: sast-triage.sarif
```

The upload never sends a stale file: the `rm` step leaves nothing at the path, and the `if` is false when
the scan step was skipped or the file is missing (`hashFiles` is then empty), and true after a failed gate
too. Use a path the repository does not use, since the `rm` step removes whatever is there. Paths in the
file are relative to `path`; code scanning reads them from the repository root, which is the default
`path: .`.

## Command line

Requires Python 3.11–3.14.

```bash
git clone https://github.com/lansiquo/sast-triage.git
python3 -m venv sast-venv
sast-venv/bin/pip install -r sast-triage/requirements-cli.txt
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project                     # whole project
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project --base origin/main  # changes since main
```

`requirements-cli.txt` installs only Semgrep (pinned to the tested 1.79.0) and certifi; set `SEMGREP_BIN`
to use another Semgrep. A scan needs no GitHub account, token or network.

```text
scan_repo.py DIRECTORY [--base REF] [--json] [--markdown FILE] [--sarif FILE] [--timeout SECONDS] [--github-annotations]
```

| Option | Effect |
|---|---|
| none | A full scan: every supported file is scanned and every finding counts as new, also those an existing codebase already had |
| `--base REF` | Scans only the files changed since the merge base of `REF` and `HEAD`, and labels each finding as for a pull request: see [How triage works](#how-triage-works) |
| `--json` | Prints the result as JSON instead of the report |
| `--markdown FILE` | Also writes the Markdown summary to `FILE`. It is written only when the scan issues a result (exit status 0 or 1): a scan that stops with exit status 2 creates no file and leaves an existing file with its old content, apart from the cases under [Exit codes](#exit-codes) |
| `--timeout SECONDS` | Limits the scan (default: 300 seconds) |
| `--sarif FILE` | Also writes the findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) file |
| `--github-annotations` | Also prints, after the report, one GitHub Actions [workflow command](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) per finding, which GitHub shows as an annotation on the workflow run and on the pull request's files |

The SARIF file and the annotations follow the Check Run's levels: `error` (`::error`) for a new P1,
`warning` (`::warning`) for a new P2, and `note` (`::notice`) otherwise. Apart from the errors under
[Exit codes](#exit-codes), neither option changes the exit status or the rest of the output.

**SARIF.** The file has one result per finding, in the same order as `--json`, with the finding's rule ID,
path, lines, fingerprint, priority, new or pre-existing label and CWE, so GitHub code scanning and other
SARIF tools can read it. It is written only when the scan issues a result (exit status 0 or 1): a scan
that stops with exit status 2 writes nothing and leaves an existing file untouched.

**Annotations.** At most 200 commands are printed, P1 first. GitHub itself
[currently shows](https://github.com/actions/toolkit/blob/main/docs/problem-matchers.md#limitations) no
more than 10 errors, 10 warnings and 10 notices from one step, so the report above the commands stays the
full list. `scan_repo.py tests/fixtures/project --github-annotations` ends with one line for each of the
fixture's two findings. The first:

```text
::error file=tests/fixtures/project/server.js,line=2,endLine=2,title=[P1%2C new] eval() runs code built at runtime (possible code injection)::eval() runs code built at runtime (possible code injection)%0ARule: js-dangerous-eval, CWE-95
```

`file` is `DIRECTORY` (in the Action, the `path` input) joined with the finding's path: run the command
from the repository root, or give an absolute `DIRECTORY`, so the annotations land on the files. Text is
escaped so that a file name can't add a command of its own;
[ARCHITECTURE.md](ARCHITECTURE.md#security-controls) says how.

**Skipped files.** A full scan skips files in `.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `dist`,
`build`, `coverage`, `.venv`, `venv` and `__pycache__` folders, and minified `*.min.js`, `*.min.mjs` and
`*.min.cjs` files. With `--base`, changed files in `vendor`, `dist`, `build` and `coverage` are scanned
too, as the GitHub App scans them; changed files it still skips are listed. The project's git diff
helpers are not used.

## Install as a package (local build)

The command line can also be installed as a `sast-triage` command. The package is not published to PyPI or
to any other index, so `pip install sast-triage` does not install this project: build the wheel from the
clone. After the [command line](#command-line) setup:

```bash
sast-venv/bin/python -m pip install "setuptools>=77.0.3"
sast-venv/bin/python -m pip wheel --no-deps --no-build-isolation --no-index -w sast-wheel ./sast-triage
sast-venv/bin/python -m pip install --no-index sast-wheel/sast_triage-*.whl
sast-venv/bin/sast-triage /path/to/project --base origin/main
```

`sast-triage` takes the arguments of `python scan_repo.py`, prints the same report and exits with the same
status; its usage and error text name `sast-triage` instead of `scan_repo.py`. Only the first command
downloads anything: setuptools, the build backend. The wheel holds only the command line, not the GitHub
App or its worker, and installs its modules under the names `scan_repo`, `trusted_rules` and `analyzers`,
so use a virtual environment of its own, as here. [CONTRIBUTING.md](CONTRIBUTING.md#package-build) covers
the build and `make package-check`, which tests it.

## Example: OWASP NodeGoat

I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Express and
MongoDB app for learning the OWASP Top 10. The results below are from its latest commit, `c5cb68a`
(June 2023). After the [command line](#command-line) setup:

```bash
git clone https://github.com/OWASP/NodeGoat.git
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat                # whole project
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat --base HEAD~2  # last two pull requests
```

The whole-project scan, without the closing legend and with the gate's repeat of the seven P1 lines
shortened:

```text
sast-triage full scan of NodeGoat
Full scan: every finding counts as new (there is no diff).
44 Python, JavaScript and TypeScript files, 41 service-owned rules.
Skipped: .git, node_modules, vendor, dist, build, coverage, .hg, .svn, .venv, venv, __pycache__ folders and minified *.min.js files.

Full scan (44 files): FAILURE
  [P1, new] Gruntfile.js:165  js-child-process-exec
  [P1, new] app/data/allocations-dao.js:78  js-nosql-injection
  [P1, new] app/routes/contributions.js:32  js-dangerous-eval
  [P1, new] app/routes/contributions.js:33  js-dangerous-eval
  [P1, new] app/routes/contributions.js:34  js-dangerous-eval
  [P1, new] app/routes/research.js:16  js-ssrf
  [P1, new] config/env/all.js:8  js-hardcoded-session-secret
  [P2, new] app/routes/index.js:72  js-open-redirect
  [P2, new] server.js:78  js-cookie-without-secure
  [P2, new] server.js:137  js-template-autoescape-disabled
### sast-triage — Semgrep summary

**Gate: FAIL** — 7 new P1 findings:
- … (the seven P1 findings above)

| Priority | New | Pre-existing |
|---|---|---|
| P1 | 7 | 0 |
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
- **Server-side request forgery:** `research.js` fetches a URL built from the `url` and `symbol` query
  parameters.

`Gruntfile.js:165` is not one of the lessons: the `db-reset` build task runs a shell command built from
`NODE_ENV` and a task argument. It is a real injection sink, but only whoever runs Grunt controls it.

**Missed:** log injection (A1), plain-text passwords (A2), insecure direct object references (A4), missing
security headers (A5), plain HTTP (A6), missing access control on `/benefits` (A7), CSRF (A8), vulnerable
dependencies (A9, see [sca-triage](https://github.com/lansiquo/sca-triage)) and a ReDoS-prone regex in
`profile.js`. No rule covers them, HTML templates are not scanned, and a request value passed to another
module before it reaches a query is not traced.

`--base HEAD~2` reviews NodeGoat's last two pull requests the way the gate reviews a pull request:
`HEAD~2` is the commit just before them. [#233](https://github.com/OWASP/NodeGoat/pull/233) moved the
tutorial routes out of `app/routes/index.js` into a new `tutorial.js`, and #290 only edited an HTML view.
Of the 2 changed files it scans, the report lists:

```text
Changes since HEAD~2 (2 files): SUCCESS
  [P2, pre-existing] app/routes/index.js:72  js-open-redirect
```

Its summary reads "**Gate: PASS** — no new P1 findings. Anything else is annotated but doesn't fail the
check." and counts one pre-existing P2 and nothing else.

**Why this passes when the whole-project scan fails.** These pull requests introduced no new P1:

- The open redirect is in a file #233 changed, but not on a line it changed, so it is pre-existing. It is
  also P2, which never fails the gate.
- The other nine findings, including all seven P1s, are in files neither pull request touched, so they are
  not scanned.

The seven P1s are still in the project; they just aren't these pull requests' doing. The
[case study](https://dotrobin.dev/sast-triage.html) shows both runs.

## How triage works

| | Meaning | When new |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the gate |
| **P2** | High or critical in test code, or medium in runtime code | Reported; a warning on the Check Run |
| **P3** | Everything else | Reported; a notice on the Check Run |

**New or pre-existing.** A finding is new if it covers a line the pull request (or, from the command line,
the changes since `--base`) added or changed. A finding on untouched lines is new too when the file didn't
have it before: the base version of a changed file is scanned too, so editing one line can't slip in a
finding on another. Only files with a finding on untouched lines need it, so most pull requests are
scanned once. Changing `const cmd = 'ls'` to `'ls ' + req.query.dir` makes the untouched
`exec(cmd)` below it a new P1. Pre-existing findings are still reported, as notices.

- No diff for a file (too large or unreadable): every finding in it counts as new.
- Base version missing, over 1 MiB or not scannable: every finding in the file counts as new.
- Renamed with no changes: unchanged.
- Renamed or copied from test code to runtime code: every finding counts as new, since its priority went up.

**Test code** follows pytest, Django and JavaScript naming: a `test` or `tests` folder or a `test_*` name;
for Python also `*_test.py` or `tests.py`; for JavaScript and TypeScript also a `__tests__`, `spec`,
`specs`, `e2e` or `cypress` folder, or a `*.test.*` or `*.spec.*` name. `conftest.py` always counts as
runtime code. A rule that rates its own confidence or likelihood `LOW` drops one level.

**Gate.** It fails only when a finding is both new and P1. Scanner errors and partial results also fail it;
only a complete scan can pass.

## Rules

`trusted_rules.py` holds all 41 service-owned rules. Rule severity ERROR is high and WARNING is medium.

**Request data reaching a dangerous call** (8 rules, Semgrep taint mode). They follow data from the
request (Flask and Django `request.args`, `form`, `json`, `GET`, `POST`, cookies and headers; Express
`req.query`, `body`, `params`, cookies and headers) through assignments, concatenation, formatting and
calls such as `os.path.join` and `path.join`, within one function:

| Rule | Severity | CWE | Flags request data reaching |
|---|---|---|---|
| `py-sql-injection`, `js-sql-injection` | high | 89 | a SQL query: `execute`, `executemany`, Django `raw`; `query`, `execute`, `knex.raw`, Prisma `$queryRawUnsafe` |
| `py-path-traversal`, `js-path-traversal` | high | 22 | a file path: `open`, Flask `send_file`, `fs.readFile`, `createReadStream`, `writeFile` and others, `res.sendFile` and `res.download` without a `root` |
| `py-ssrf`, `js-ssrf` | high | 918 | the URL of an outgoing request: `requests`, `httpx`, `urlopen`, `fetch`, `axios`, `got`, `needle`, `http(s).get` |
| `py-xss`, `js-xss` | high | 79 | an HTML response: a Flask route's return value, `make_response`, `Markup`, `render_template_string`, Django `HttpResponse`, `res.send`, `res.write`, `res.end` |

A number parsed from request data (`int`, `parseInt`), a value passed through an escaping or path
function (`escape`, `secure_filename`, `path.basename`) and a record looked up with it
(`User.objects.get(...)`, `User.findById(...)`) no longer count as request data. A URL that starts with a
fixed `https://host/` can't be pointed at another server, and an object sent with `res.send` goes out as
JSON. A query that only has request data in its parameters is fine. For cross-site scripting, data only
counts when it is copied, concatenated or formatted into the response, not passed through a call: a
file's contents or an API's response is not request data.

`py-sql-formatted-query` and `js-sql-formatted-query` (medium, CWE-89) flag a SQL query built with `%`,
`format`, an f-string, `+` or a template literal from any value. When the same line also carries request
data, only the high-severity finding is reported. `py-weak-password-hash` and `js-weak-password-hash`
(high, CWE-916) flag md5 or sha1 applied to something named like a password, passphrase or secret.

**Python (15 more).** High: `yaml.load` without a safe loader, `yaml.unsafe_load`, `pickle.load` and
`pickle.loads`; `os.system`, `os.popen` and `subprocess` with `shell=True`; `eval` and `exec`; `requests`
with `verify=False`; `tarfile.extractall`. Medium: `hashlib.md5` and `sha1` (not with
`usedforsecurity=False`); the `random` module; `tempfile.mktemp`.

**JavaScript and TypeScript (14 more):**

| Rule | Severity | CWE | Flags |
|---|---|---|---|
| `js-dangerous-eval` | high | 95 | `eval()` of anything but a string literal |
| `js-implied-eval` | high | 95 | `Function` with a non-literal body; `setTimeout` or `setInterval` with a string built at runtime |
| `js-vm-dynamic-code` | high | 95 | `vm.runInContext`, `runInNewContext`, `runInThisContext`, `compileFunction` or `new vm.Script` with non-literal code |
| `js-child-process-exec` | high | 78 | `child_process` `exec` or `execSync` with a non-literal command |
| `js-insecure-deserialization-node-serialize` | high | 502 | `node-serialize` `unserialize()` |
| `js-weak-hash` | medium | 327 | `createHash('md5')` or `createHash('sha1')` |
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
to 200 annotations, P1 first. It needs the full `requirements.txt`:

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

This local mode scans in the web process, two at a time. The durable mode (SQLite queue, separate worker,
rootless Docker sandbox) is prepared but not live; see [deploy/README.md](deploy/README.md).

## Exit codes

| Code | `scan_repo.py`, `sast-triage` and the GitHub Action |
|---|---|
| 0 | The gate passes: no new P1 finding, or nothing to scan |
| 1 | The gate fails: at least one new P1 finding |
| 2 | Usage, git or scanner error, such as a missing directory, a `--timeout` that is not a whole number, `--github-annotations` with `--json`, a `--base` ref that is not a commit in the checkout or has no merge base with `HEAD` (the error says what to fetch), a folder that can't be read, an incomplete scan, or a `--markdown` or `--sarif` destination that can't be written |

With exit status 2 no result is issued: no report or workflow command is printed, no `--markdown` or
`--sarif` file is created, an existing one keeps its old content, and the Action adds no summary. The SARIF
file is renamed into place after the Markdown file is written; if that rename fails, for example because the
destination is another user's file in a sticky folder such as `/tmp`, the Markdown file is removed if the
scan created it, or its old content is written back. One case is not undone: if the scan can't read the
existing Markdown file (no read permission, or not a regular file, such as `/dev/stdout`), or removing a new
one or writing the old content back fails, the Markdown destination is left changed, and a second `error:`
line names it. Apart from that, a Markdown file whose own write fails partway, for example on a full disk, can
be left partly written; the SARIF file is then not changed.

## Scope and limits

- **Rules match within one file.** A value that passes through another function or module before it
  reaches a dangerous call is not traced.
- **New is judged file by file.** A finding is matched to the base version by its rule and the text of
  the lines it covers. Only changed files are scanned, so a change in one file can't raise a finding in
  another that it didn't touch.
- **Size limits fail closed:** 1 MiB per scanned file; for the GitHub App also a 1 MiB webhook body,
  fewer than 3,000 changed files and at most 500 changed Python, JavaScript and TypeScript files per pull
  request. The App downloads only those files, so the size of the repository doesn't matter.
- **Local mode is not an OS sandbox.** It strips credentials from the scanner and stages only the selected
  files. Before scanning untrusted public repositories, use the durable mode's isolated worker.

## More

- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [ARCHITECTURE.md](ARCHITECTURE.md): components, execution modes, failure handling and security controls, with a diagram
- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, tests, the package build and repository layout
- [Case study](https://dotrobin.dev/sast-triage.html): design and runs on OWASP NodeGoat
