# Command line

The [README](../README.md#command-line) has the setup. This page covers every option, the output files,
the files a scan skips, the package build and the exit codes.

## Setup

- Requires Python 3.11–3.14.
- `requirements-cli.txt` installs only Semgrep (pinned to the tested 1.79.0) and certifi.
- Set `SEMGREP_BIN` to use another Semgrep.
- Leave `PRSEC_SEMGREP_MIN_SEVERITY` unset. If set, findings below that severity are dropped before
  triage, so they are never reported and can't fail the gate: see
  [Severity floor](github-app.md#severity-floor).
- A scan needs no GitHub account, token or network.

## Options

```text
scan_repo.py DIRECTORY [--base REF] [--json] [--markdown FILE] [--sarif FILE] [--timeout SECONDS] [--github-annotations]
```

| Option | Effect |
|---|---|
| none | A full scan: every supported file is scanned and every finding counts as new, also those an existing codebase already had |
| `--base REF` | Scans only the files changed since the merge base of `REF` and `HEAD`, and labels each finding as for a pull request: see [How triage works](triage.md) |
| `--json` | Prints the result as JSON instead of the report |
| `--markdown FILE` | Also writes the Markdown summary to `FILE`. It is written only when the scan issues a result (exit status 0 or 1): a scan that stops with exit status 2 creates no file and leaves an existing file with its old content, apart from the cases under [Exit codes](#exit-codes) |
| `--timeout SECONDS` | Limits the scan (default: 300 seconds) |
| `--sarif FILE` | Also writes the findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) file |
| `--github-annotations` | Also prints, after the report, one GitHub Actions [workflow command](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) per finding, which GitHub shows as an annotation on the workflow run and on the pull request's files |

## SARIF and annotations

The SARIF file and the annotations follow the Check Run's levels:

- `error` (`::error`) for a new P1.
- `warning` (`::warning`) for a new P2.
- `note` (`::notice`) otherwise.

Apart from the errors under [Exit codes](#exit-codes), neither option changes the exit status or the rest
of the output.

**SARIF.** The file has one result per finding, in the same order as `--json`. Each result has the
finding's rule ID, path, lines, fingerprint, priority, new or pre-existing label and CWE, so GitHub code
scanning and other SARIF tools can read it. It is written only when the scan issues a result (exit status
0 or 1). A scan that stops with exit status 2 writes nothing and leaves an existing file untouched.

**Annotations.** At most 200 commands are printed, P1 first. GitHub itself
[currently shows](https://github.com/actions/toolkit/blob/main/docs/problem-matchers.md#limitations) no
more than 10 errors, 10 warnings and 10 notices from one step, so the report above the commands stays the
full list. `scan_repo.py tests/fixtures/project --github-annotations` ends with one line for each of the
fixture's two findings. The first:

```text
::error file=tests/fixtures/project/server.js,line=2,endLine=2,title=[P1%2C new] eval() runs code built at runtime (possible code injection)::eval() runs code built at runtime (possible code injection)%0ARule: js-dangerous-eval, CWE-95
```

`file` is `DIRECTORY` (in the Action, the `path` input) joined with the finding's path. Run the command
from the repository root, or give an absolute `DIRECTORY`, so the annotations land on the files. Text is
escaped so that a file name can't add a command of its own;
[ARCHITECTURE.md](../ARCHITECTURE.md#security-controls) says how.

## Skipped files

A full scan skips files in `.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `dist`, `build`, `coverage`,
`.venv`, `venv` and `__pycache__` folders, and minified `*.min.js`, `*.min.mjs` and `*.min.cjs` files.
It also skips Python packages under any folder name: every folder with a `pyvenv.cfg` file (a virtual
environment, such as `sast-venv`) and every `site-packages` or `dist-packages` folder.

When the directory is in a git work tree, a full scan reads only the files that
`git ls-files --cached --others --exclude-standard` lists: tracked files, even if a `.gitignore` pattern
matches them, and untracked files git does not ignore. A folder git ignores, such as an untracked build
output, is not scanned; a submodule or nested repository is not either. If git fails, the scan stops with
exit status 2. Outside a work tree every folder is read.

The report, the Markdown summary and `--json` (`skipped_paths`, each with a `reason`) name what these rules
left out, for example `Skipped: sast-venv/ (virtual environment), 3 paths git ignores.`

With `--base`, changed files in `vendor`, `dist`, `build` and `coverage` are scanned too, as the GitHub
App scans them. Changed files it still skips are listed. The project's git diff helpers are not used.

## Install as a package

The README's [package steps](../README.md#install-as-a-package-local-build) build and install a
`sast-triage` command. The package is not published to PyPI or to any other index, so
`pip install sast-triage` does not install this project.

- `sast-triage` takes the arguments of `python scan_repo.py`, prints the same report and exits with the
  same status. Its usage and error text name `sast-triage` instead of `scan_repo.py`.
- Only the first command downloads anything: setuptools, the build backend.
- The wheel holds only the command line, not the GitHub App or its worker.
- It installs its modules under the names `scan_repo`, `trusted_rules` and `analyzers`, so use a virtual
  environment of its own, as the README does.

[CONTRIBUTING.md](../CONTRIBUTING.md#package-build) covers the build and `make package-check`, which tests
it.

## Exit codes

| Code | `scan_repo.py`, `sast-triage` and the GitHub Action |
|---|---|
| 0 | The gate passes: no new P1 finding, or nothing to scan |
| 1 | The gate fails: at least one new P1 finding |
| 2 | Usage, git or scanner error, such as a missing directory, a `--timeout` that is not a whole number, `--github-annotations` with `--json`, a `--base` ref that is not a commit in the checkout or has no merge base with `HEAD` (the error says what to fetch), a folder that can't be read, an incomplete scan, or a `--markdown` or `--sarif` destination that can't be written |

With exit status 2 no result is issued:

- No report or workflow command is printed.
- No `--markdown` or `--sarif` file is created, and an existing one keeps its old content.
- The Action adds no summary.

The SARIF file is renamed into place after the Markdown file is written. If that rename fails, for example
because the destination is another user's file in a sticky folder such as `/tmp`, the Markdown file is
removed if the scan created it, or its old content is written back.

One case is not undone. If the scan can't read the existing Markdown file (no read permission, or not a
regular file, such as `/dev/stdout`), or removing a new one or writing the old content back fails, the
Markdown destination is left changed, and a second `error:` line names it.

Apart from that, a Markdown file whose own write fails partway, for example on a full disk, can be left
partly written. The SARIF file is then not changed.
