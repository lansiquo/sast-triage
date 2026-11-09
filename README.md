# sast-triage

A GitHub App service that reviews pull requests with Semgrep. It labels each finding **new** or **pre-existing** from the pull request's diff, ranks it **P1–P3**, and fails the check only on new P1 findings. A pull request is blocked by what it introduced, not by what was already there.

It runs 29 service-owned rules for high-signal Python, JavaScript and TypeScript patterns (`.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`). Rules, ignore files and `nosemgrep` comments from the pull request are not used. Findings are review aids, not a security audit. For npm dependencies, see the companion [sca-triage](https://github.com/lansiquo/sca-triage).

The same rules, triage and gate also run on a whole repository from the command line (`scan_repo.py`). On OWASP NodeGoat, an intentionally vulnerable Express and MongoDB app, they find its `eval` code injection, NoSQL injection, open redirect, hard-coded session secret, insecure session cookie and disabled template escaping; see [Example: OWASP NodeGoat](#example-owasp-nodegoat).

**Status: v1.0.** Runs locally and in its own CI; live GitHub deployment is prepared and not yet complete.

## Quick start

Requires Python 3.11–3.14. `requirements.txt` resolves to Semgrep 1.79.0: newer Semgrep pins `opentelemetry-api` below the version current FastAPI needs, and forcing it would also pull in `mcp` and `opentelemetry-api` releases with known advisories. Set `SEMGREP_BIN` to use another Semgrep. The tests, the demo and full-repository scans need no GitHub account, token or network.

```bash
git clone https://github.com/lansiquo/sast-triage.git
cd sast-triage
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

```bash
make test     # offline regression suite (176 tests), outbound HTTP blocked
make demo     # a small built-in pull request example; prints triage and annotation JSON
make check    # test, then demo
```

To scan a whole repository, run `scan_repo.py` on its folder (see the NodeGoat example below):

```bash
.venv/bin/python scan_repo.py path/to/project          # report; add --json for machine-readable output
```

It scans every Python, JavaScript and TypeScript file except those in `.git`, `node_modules`, `vendor`, `dist`, `build`, `coverage` and virtualenv folders, and minified `*.min.js` files. There is no diff, so every finding counts as new. The exit status is 1 when the gate fails (a new P1), 0 when it passes and 2 on a usage or scanner error. The project is only parsed, never run or installed, and its own Semgrep rules and ignore files are not used.

To run the webhook service against a GitHub App:

```bash
cp .env.example .env   # set GITHUB_WEBHOOK_SECRET, GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_PATH
make serve             # http://127.0.0.1:8000, liveness at /health
```

The app reads `.env` only when `PRSEC_LOAD_DOTENV=1`, which `make serve` sets. Otherwise it takes configuration from the environment. The App needs **pull request** events with Contents read, Pull requests read and Checks write. A real webhook creates real Check Runs, so use a test repository.

## How triage works

**New or pre-existing.** A finding is new if it covers a line the pull request added or changed. Pre-existing findings are still annotated, as notices.

- No diff for a file (too large or unreadable): every finding in it counts as new.
- Renamed with no changes: unchanged.
- Renamed or copied from test code to runtime code: every finding counts as new, since its priority went up.

**Priority.**

| | Meaning | On the Check Run |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the check when new |
| **P2** | High or critical in test code, or medium in runtime code | Warning when new |
| **P3** | Everything else | Notice |

Test code follows pytest, Django and JavaScript naming: a `test` or `tests` folder or a `test_*` name; for Python also `*_test.py` or `tests.py`; for JavaScript and TypeScript also a `__tests__`, `spec`, `specs`, `e2e` or `cypress` folder, or a `*.test.*` or `*.spec.*` name. `conftest.py` always counts as runtime code. A rule that rates its own confidence or likelihood `LOW` drops one level.

**Gate.** The check fails only when a finding is both new and P1. Scanner errors and partial results also fail it; only a complete scan can pass.

## Example: OWASP NodeGoat

[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) is a deliberately vulnerable Express and MongoDB app for learning the OWASP Top 10. To scan it at commit `c5cb68a`, from the sast-triage folder:

```bash
git clone https://github.com/OWASP/NodeGoat.git ../NodeGoat
git -C ../NodeGoat checkout c5cb68a
.venv/bin/python scan_repo.py ../NodeGoat     # exit status 1: the gate fails
```

The output, without the closing priority legend and with the gate's repeat of the six P1 lines shortened to one:

```text
sast-triage full scan of ../NodeGoat
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
- **Session management (A2):** the session secret is hard-coded (`cookieSecret` in `config/env/all.js`), and `server.js` configures `express-session` without `cookie.secure`.
- **Cross-site scripting (A3):** `server.js` turns off Swig's autoescaping for every template.
- **Open redirect (A10):** `/learn` redirects to `req.query.url`.

`Gruntfile.js:165` is not one of the lessons: the `db-reset` build task runs a shell command built from `NODE_ENV` and a task argument. It is a real injection sink, but only whoever runs Grunt controls it.

**Missed:** log injection (A1), plain-text passwords (A2), insecure direct object references (A4), missing security headers (A5), plain HTTP (A6), missing access control on `/benefits` (A7), CSRF (A8), vulnerable dependencies (A9, see [sca-triage](https://github.com/lansiquo/sca-triage)), server-side request forgery in `research.js` and a ReDoS-prone regex in `profile.js`. No rule covers them, and HTML templates are not scanned. The rules also match within one file, so a request value passed to another module before it reaches a query is not traced.

`make demo` runs a small built-in example instead: one simulated Python pull request, where a new P1 fails the check and a pre-existing one does not.

## Rules

`trusted_rules.py` holds all 29 service-owned rules. Rule severity ERROR is high and WARNING is medium.

**Python (15):** `hashlib.md5` and `sha1`; `yaml.load` without a safe loader, `yaml.unsafe_load`, `pickle.load` and `pickle.loads`; `os.system`, `os.popen` and `subprocess` with `shell=True`; `eval` and `exec`; `requests` with `verify=False`; the `random` module; `tempfile.mktemp`; `tarfile.extractall`.

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

## Local interactive showcase

```bash
.venv/bin/python demo_web.py   # http://127.0.0.1:8765
```

Steps through ten OWASP Top 10:2025 examples: four run real Semgrep scans, six run behavioral tests on bundled fixtures. The pull request view is simulated. See [deploy/local-showcase.md](deploy/local-showcase.md).

## Layout

| Path | Contents |
|---|---|
| `app.py` | Webhook service and scan pipeline |
| `analyzers/` | Semgrep runner and triage |
| `trusted_rules.py` | The 29 service-owned rules |
| `scan_repo.py` | Full-repository scan from the command line |
| `rules/` | Extra Semgrep rule packs for manual scans; the service does not load them |
| `worker.py`, `job_store.py` | Durable mode: SQLite queue and separate worker |
| `demo.py` | Offline demo (`make demo`) |
| `demo_web.py`, `demo/` | Local interactive showcase |
| `tests/` | Offline regression suite (`make test`) |
| `deploy/` | Prepared deployment design, runbooks and evidence |
| `docs/branch-protection/` | Branch protection that makes the check required, for a repository that uses the App |
| `.github/workflows/ci.yml` | Runs `make check` on every pull request and push to main |

## Scope and limits

- **Rules match within one file.** A value that passes through another function or module before it reaches a dangerous call is not traced.
- **Pre-existing means untouched, not unrelated.** A change elsewhere (for example, a new import) can make an untouched line match; that finding stays pre-existing and doesn't fail the check.
- **Size limits fail closed:** 1 MiB webhook body, 25 MiB archive, 100 MiB extracted, 10,000 archive members, 3,000 changed files.
- **Local mode is not an OS sandbox.** It strips credentials from the scanner and stages only the selected files. Before scanning untrusted public repositories, use the durable mode's isolated worker.

## Deployment

The durable mode and rootless Docker sandbox are prepared but not live. See [deploy/README.md](deploy/README.md).

## More

- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup
- Write-up: [dotrobin.dev/sast-triage](https://dotrobin.dev/sast-triage.html)
- [Browser demo](https://dotrobin.dev/demos/sast.html): ten curated OWASP Top 10:2025 examples, triaged in the browser with no setup and no scanning
