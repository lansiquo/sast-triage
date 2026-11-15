# GitHub Action

The [README](../README.md#github-action) has the workflow steps, the inputs table and an example job that
uploads to code scanning. This page has the details behind them.

## Inputs

All five inputs are optional.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan |
| `base` | `""` | Git ref to compare with. Empty: the pull request's base branch, or a full scan on other events. `none`: always a full scan |
| `timeout` | `""` | Scanner time limit in seconds, passed as `--timeout`. Empty: the default of 300 seconds |
| `sarif` | `""` | File to also write the findings to, passed as `--sarif`. A relative path is relative to the workspace. Empty: no SARIF file |
| `annotations` | `"false"` | `"true"` adds `--github-annotations`. `"false"` adds nothing. Any value other than `"true"` or `"false"`, an empty one included, stops the step with exit status 2 before the scan |

The checkout needs `fetch-depth: 0`, so the base branch's history is there to diff against.

## What the step does

- It fails when the gate fails, and it adds the summary to the job summary.
- It installs only `requirements-cli.txt` with the runner's Python.
- It uses no token and no other actions.
- Annotations need no added permission.

## Pin a version

Pin a release tag such as `@v2.6.3`, or a full commit SHA for the strictest supply-chain safety.

A pull request that can edit the workflow can edit this step too. The
[GitHub App](github-app.md) runs outside the repository's workflows.

## Upload the SARIF file to code scanning

The Action does not upload the SARIF file. To show the findings in GitHub code scanning, upload it in a
separate step of your own workflow, pinned to a full commit SHA. The job needs these permissions:

- `contents: read` for the checkout.
- `security-events: write` for the upload step.
- `actions: read` for the upload step, only in a private repository.

The README's example job never uploads a stale file:

- The `rm -rf sast-triage.sarif` step leaves nothing at the path. Anything already there is not this
  scan's result.
- The upload step's `if` is false when the scan step was skipped or the file is missing (`hashFiles` is
  then empty). It is true after a failed gate too.
- Use a path the repository does not use, since the `rm` step removes whatever is there.

Paths in the file are relative to `path`. Code scanning reads them from the repository root, which is the
default `path: .`.

The SARIF file's contents and the annotation format are in
[command-line.md](command-line.md#sarif-and-annotations).
