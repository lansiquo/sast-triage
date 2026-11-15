# Rules

`trusted_rules.py` holds all 41 service-owned rules for high-signal patterns: 21 for Python and 20 for
JavaScript and TypeScript. They scan `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts` and `.tsx` files. Rule
severity ERROR is high and WARNING is medium. [How triage works](triage.md) turns severity into P1–P3.

A scan reads source files only: nothing in the project is run or installed. The scanned code's own rules,
ignore files and `nosemgrep` comments are not used, and Semgrep never downloads rules. Extra rule packs in
`rules/` are for manual scans only; the service does not load them.

## Request data reaching a dangerous call

These 8 rules use Semgrep taint mode. They follow data from the request through assignments,
concatenation, formatting and calls such as `os.path.join` and `path.join`, within one function:

- Flask and Django: `request.args`, `form`, `json`, `GET`, `POST`, cookies and headers.
- Express: `req.query`, `body`, `params`, cookies and headers.

| Rule | Severity | CWE | Flags request data reaching |
|---|---|---|---|
| `py-sql-injection`, `js-sql-injection` | high | 89 | a SQL query: `execute`, `executemany`, Django `raw`; `query`, `execute`, `knex.raw`, Prisma `$queryRawUnsafe` |
| `py-path-traversal`, `js-path-traversal` | high | 22 | a file path: `open`, Flask `send_file`, `fs.readFile`, `createReadStream`, `writeFile` and others, `res.sendFile` and `res.download` without a `root` |
| `py-ssrf`, `js-ssrf` | high | 918 | the URL of an outgoing request: `requests`, `httpx`, `urlopen`, `fetch`, `axios`, `got`, `needle`, `http(s).get` |
| `py-xss`, `js-xss` | high | 79 | an HTML response: a Flask route's return value, `make_response`, `Markup`, `render_template_string`, Django `HttpResponse`, `res.send`, `res.write`, `res.end` |

What no longer counts as request data:

- A number parsed from request data (`int`, `parseInt`).
- A value passed through an escaping or path function (`escape`, `secure_filename`, `path.basename`).
- A record looked up with it (`User.objects.get(...)`, `User.findById(...)`).

What these rules don't flag:

- A URL that starts with a fixed `https://host/`: it can't be pointed at another server.
- An object sent with `res.send`: it goes out as JSON.
- A query that only has request data in its parameters.
- For cross-site scripting, data passed through a call. Data only counts when it is copied, concatenated
  or formatted into the response. A file's contents or an API's response is not request data.

## SQL queries and password hashes

- `py-sql-formatted-query` and `js-sql-formatted-query` (medium, CWE-89) flag a SQL query built with `%`,
  `format`, an f-string, `+` or a template literal from any value. When the same line also carries
  request data, only the high-severity finding is reported.
- `py-weak-password-hash` and `js-weak-password-hash` (high, CWE-916) flag md5 or sha1 applied to
  something named like a password, passphrase or secret.

## Python (15 more)

- High: `yaml.load` without a safe loader, `yaml.unsafe_load`, `pickle.load` and `pickle.loads`;
  `os.system`, `os.popen` and `subprocess` with `shell=True`; `eval` and `exec`; `requests` with
  `verify=False`; `tarfile.extractall`.
- Medium: `hashlib.md5` and `sha1` (not with `usedforsecurity=False`); the `random` module;
  `tempfile.mktemp`.

## JavaScript and TypeScript (14 more)

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
