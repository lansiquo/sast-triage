# sast-triage

sast-triage runs Semgrep on Python, JavaScript and TypeScript code. It labels each finding **new** or
**pre-existing**, ranks it **P1–P3**, and fails the check only on new P1 findings. A pull request is
blocked by what it adds, not by what was already there.

Findings are review aids, not a security audit. Its companion
[sca-triage](https://github.com/lansiquo/sca-triage) ranks npm dependency vulnerabilities P1–P3 the same way.

## Status

- Latest release: [v2.6.3](https://github.com/lansiquo/sast-triage/releases/tag/v2.6.3).
- Use the GitHub Action or the command line.
- The [GitHub App](docs/github-app.md) service runs locally. Its durable mode is prepared but not live.

## GitHub Action

In a workflow that runs on `pull_request`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0               # needed for the diff
- uses: lansiquo/sast-triage@v2.6.3
  with:                          # the defaults
    path: .
    base: ""
    timeout: ""                  # 300 seconds
    sarif: ""                    # no file
    annotations: "false"         # off
```

All five inputs are optional (defaults shown):

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan |
| `base` | `""` | Ref to compare with. Empty: the pull request's base branch, or a full scan on other events. `none`: a full scan |
| `timeout` | `""` | Scanner time limit in seconds, passed as `--timeout`. Empty: 300 seconds |
| `sarif` | `""` | Also write the findings to this file, passed as `--sarif` |
| `annotations` | `"false"` | `"true"` adds `--github-annotations`. `"false"` adds nothing. Other values stop the step with exit status 2 |

The step fails when the gate fails and writes the job summary. It installs only `requirements-cli.txt`,
and it uses no token and no other actions.

Code scanning needs your own upload step, with `security-events: write`:

```yaml
on: pull_request
jobs:
  sast-triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read                # private repositories only
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: rm -rf sast-triage.sarif          # remove any stale file
      - id: scan
        uses: lansiquo/sast-triage@v2.6.3
        with:
          sarif: sast-triage.sarif
      - if: ${{ !cancelled() && steps.scan.outcome != 'skipped' && hashFiles('sast-triage.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066   # v4.39.3
        with:
          sarif_file: sast-triage.sarif
```

[docs/github-action.md](docs/github-action.md) has the details.

## Command line

Requires Python 3.11–3.14. A scan needs no GitHub account, token or network. Replace `/path/to/project`
with your folder:

```bash
git clone https://github.com/lansiquo/sast-triage.git
python3 -m venv sast-venv
sast-venv/bin/pip install -r sast-triage/requirements-cli.txt
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project                     # whole project
sast-venv/bin/python sast-triage/scan_repo.py /path/to/project --base origin/main  # changes since main
```

```text
scan_repo.py DIRECTORY [--base REF] [--json] [--markdown FILE] [--sarif FILE] [--timeout SECONDS] [--github-annotations]
```

A whole-project scan skips virtual environments under any name and, in a git repository, what git
ignores, and lists what it skipped ([skipped files](docs/command-line.md#skipped-files)).
[docs/command-line.md](docs/command-line.md) explains every option.

## Install as a package (local build)

For a `sast-triage` command, build a wheel after the command line setup. The package is
not published to PyPI.

```bash
sast-venv/bin/python -m pip install "setuptools>=77.0.3"
sast-venv/bin/python -m pip wheel --no-deps --no-build-isolation --no-index -w sast-wheel ./sast-triage
sast-venv/bin/python -m pip install --no-index sast-wheel/sast_triage-*.whl
sast-venv/bin/sast-triage /path/to/project --base origin/main
```

`sast-triage` takes the arguments of `scan_repo.py` and exits with the same status. `make package-check`
tests the build. [Details](docs/command-line.md#install-as-a-package).

## How triage works

- **P1:** high or critical severity in runtime code. A new P1 fails the gate.
- **P2:** high or critical in test code, or medium in runtime code.
- **P3:** everything else.

A finding is new if it covers a changed line, or if the file's base version lacked it. Scanner errors
and partial results fail the gate: only a complete scan can pass. [docs/triage.md](docs/triage.md) has
the edge cases.

## Rules

`trusted_rules.py` holds all 41 service-owned rules. They scan `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`,
`.ts` and `.tsx` files. The taint rules follow request data into SQL, file paths, URLs and HTML
(8 rules, Semgrep taint mode). Others flag risky calls such as `eval`. [docs/rules.md](docs/rules.md)
lists them all.

## Exit codes

`scan_repo.py`, `sast-triage` and the Action exit with:

- `0`: the gate passes (no new P1 finding, or nothing to scan).
- `1`: the gate fails (at least one new P1 finding).
- `2`: a usage, git or scanner error, with no result.

[docs/command-line.md](docs/command-line.md#exit-codes) lists the errors.

## Scope and limits

- **Nothing in the scanned project is run or installed.** Its Semgrep rules, Semgrep ignore files and
  `nosemgrep` comments are not used, and Semgrep never downloads rules.
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

- [docs/nodegoat-example.md](docs/nodegoat-example.md): a scan of OWASP NodeGoat, explained
- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [ARCHITECTURE.md](ARCHITECTURE.md): components, execution modes, failure handling and security controls, with a diagram
- [SECURITY.md](SECURITY.md): trust boundaries and remaining risks
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, tests, the package build and repository layout
- [Case study](https://dotrobin.dev/sast-triage.html): design and runs on OWASP NodeGoat
