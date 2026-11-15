# Example: OWASP NodeGoat

I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Express and
MongoDB app for learning the OWASP Top 10. The results below are from its latest commit, `c5cb68a`
(June 2023). The [case study](https://dotrobin.dev/sast-triage.html) shows both runs.

## Run it

After the [command line](../README.md#command-line) setup:

```bash
git clone https://github.com/OWASP/NodeGoat.git
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat                # whole project
sast-venv/bin/python sast-triage/scan_repo.py NodeGoat --base HEAD~2  # last two pull requests
```

## Whole-project scan

The output, without the closing legend and with the gate's repeat of the seven P1 lines shortened:

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

## Pull request scan

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

The seven P1s are still in the project; they just aren't these pull requests' doing.
