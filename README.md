# sast-triage

A Semgrep reviewer for Python, JavaScript and TypeScript, run from the command line, as a GitHub Action
or as a GitHub App service. It labels each finding **new** or **pre-existing** by comparing the change with
the code before it, ranks it **P1–P3**, and fails only on new P1 findings, so a pull request is blocked by
what it introduced, not by what was already there.

A Semgrep step in a repository's own CI reports every finding with the same urgency, and the pull request
can edit that step. `sast-triage` runs 41 service-owned rules for high-signal patterns (`.py`, `.js`,
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
The output, without the legend:

```text
sast-triage scan of NodeGoat, changes since HEAD~2
A finding is new when it covers a line changed since the base, or was not in the file before; only a new P1 fails.
2 changed Python, JavaScript and TypeScript files, 41 service-owned rules.
Skipped: .git, .hg, .svn, .venv, venv, __pycache__, node_modules folders and minified *.min.js files.

Changes since HEAD~2 (2 files): SUCCESS
  [P2, pre-existing] app/routes/index.js:72  js-open-redirect
### sast-triage — Semgrep summary

**Gate: PASS** — no new P1 findings. Anything else is annotated but doesn't fail the check.

| Priority | New | Pre-existing |
|---|---|---|
| P1 | 0 | 0 |
| P2 | 0 | 1 |
| P3 | 0 | 0 |
```

**Why this passes when the whole-project scan fails.** The gate fails only on a finding that is both new
and P1, and these pull requests introduced none:

- The open redirect is in a file #233 changed, but not on a line it changed, so it is pre-existing. It is
  also P2, which never fails the gate.
- The other nine findings, including all seven P1s, are in files neither pull request touched, so they are
  not scanned.

The seven P1s are still in the project, as the whole-project scan shows. They just aren't these pull
requests' doing, so they don't block them. The [case study](https://dotrobin.dev/sast-triage.html) shows
both runs.

## Use it on your project

Requires Python 3.11–3.14. A scan reads source files only: nothing is run or installed, and it needs no
GitHub account, token or network. `requirements-cli.txt` installs only Semgrep (pinned to the tested
1.79.0) and certifi; set `SEMGREP_BIN` to use another Semgrep.

```bash
git clone https://github.com/lansiquo/sast-triage.git
python3 -m venv sast-venv
sast-venv/bin/pip install -r sast-triage/requirements-cli.txt
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project --base origin/main
```

```text
scan_repo.py DIRECTORY [--base REF] [--json] [--markdown FILE] [--sarif FILE] [--timeout SECONDS]
```

Without `--base`, every supported file is scanned and every finding counts as new, so on an existing
codebase findings that were already there count too. With `--base REF`, only the files changed since the
merge base of `REF` and `HEAD` are scanned, and a finding is new when it covers a line they added or
changed, or when the file didn't have it at the merge base: the same labels a pull request gets. `--json`
prints the result as JSON, `--markdown FILE` also writes the Markdown summary, and `--timeout` limits the
scan (default 300 seconds).

`--sarif FILE` also writes the findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
file, one result per finding in the same order as `--json`, carrying each finding's rule ID, path, lines,
fingerprint, and its priority, new or pre-existing label and CWE. Each result's level follows the Check
Run: `error` for a new P1, `warning` for a new P2 and `note` otherwise, so the file can be uploaded to
GitHub code scanning or read by other SARIF tools (uploading is the caller's own step). The file is
written whenever the scan issues a result (exit 0 or 1), including when the base versions of the changed
files cannot be scanned and every finding counts as new; a scanner, git or 1 MiB error (exit 2) writes
nothing and leaves an existing file untouched. `--sarif` changes no exit status or other output.

A full scan skips files in `.git`, `node_modules`, `vendor`, `dist`, `build`, `coverage` and virtualenv
folders, and minified `*.min.js` files. With `--base`, changed files in `vendor`, `dist`, `build` and
`coverage` are scanned too, as the GitHub App scans them; changed files it still skips are listed. A folder
that can't be read stops the scan with exit status 2. The project's own Semgrep rules, ignore files and git
diff helpers are not used.

## GitHub Action

In a workflow that runs on `pull_request`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0               # the base branch's history, to diff against it
- uses: lansiquo/sast-triage@v2.2.1
  with:
    path: .                      # directory to scan
    base: ""                     # default: the pull request's base branch; "none" for a full scan
    timeout: ""                  # scanner time limit in seconds; default: 300
```

All three inputs are optional (defaults shown):

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan |
| `base` | `""` | Git ref to compare with. Empty: the pull request's base branch, or a full scan on other events. `none`: always a full scan |
| `timeout` | `""` | Scanner time limit in seconds, passed to `scan_repo.py` as `--timeout`. Empty: its default of 300 seconds |

On a pull request it scans the files changed since the base branch; on other events, or with `base: none`,
it scans everything. The step fails when the gate fails and adds the summary to the job summary. It
installs only `requirements-cli.txt` with the runner's Python and uses no other actions. Pin a release tag
such as `@v2.2.1`, or a full commit SHA for the strictest supply-chain safety.

`timeout: 600` raises the scanner time limit from the default 300 seconds to 600, for a scan too large to
finish in 300. A value that is not a whole number, such as `timeout: abc`, stops the step with exit status
2 and no summary, as `scan_repo.py --timeout abc` does.

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

**Request data reaching a dangerous call** (12 rules, Semgrep taint mode). They follow data from the
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

**Python (15 more):** `hashlib.md5` and `sha1` (medium; not with `usedforsecurity=False`); `yaml.load`
without a safe loader, `yaml.unsafe_load`, `pickle.load` and `pickle.loads`; `os.system`, `os.popen` and
`subprocess` with `shell=True`; `eval` and `exec`; `requests` with `verify=False`; the `random` module;
`tempfile.mktemp`; `tarfile.extractall`.

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
| 2 | Usage, git or scanner error, such as a missing directory, a `--base` ref that is not a commit in the checkout or has no merge base with `HEAD` (the error says what to fetch), a folder that can't be read, a file over 1 MiB, an incomplete scan or a `--sarif` destination that can't be written; no result is issued |

## Scope and limits

- **Rules match within one file.** A value that passes through another function or module before it
  reaches a dangerous call is not traced.
- **New is judged file by file.** A finding is matched to the base version by its rule and the text of
  the lines it covers. Only changed files are scanned, so a change in one file can't raise a finding in
  another that it didn't touch.
- **Size limits fail closed:** 1 MiB per scanned file; for the GitHub App also a 1 MiB webhook body,
  3,000 changed files and 500 changed Python, JavaScript and TypeScript files per pull request. The App
  downloads only those files, so the size of the repository doesn't matter.
- **Local mode is not an OS sandbox.** It strips credentials from the scanner and stages only the selected
  files. Before scanning untrusted public repositories, use the durable mode's isolated worker.

## More

- [ARCHITECTURE.md](ARCHITECTURE.md): components, execution modes, failure handling and security controls, with a diagram
- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, tests and repository layout
- [Case study](https://dotrobin.dev/sast-triage.html): design and runs on OWASP NodeGoat
