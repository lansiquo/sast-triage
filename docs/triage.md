# How triage works

sast-triage ranks each finding, labels it new or pre-existing, and fails the gate only on new P1
findings. The command line, the GitHub Action and the GitHub App all work this way.

## Priorities

| | Meaning | When new |
|---|---|---|
| **P1** | High or critical severity in runtime code | Fails the gate |
| **P2** | High or critical in test code, or medium in runtime code | Reported; a warning on the Check Run |
| **P3** | Everything else | Reported; a notice on the Check Run |

Rule severity ERROR is high and WARNING is medium. A rule that rates its own confidence or likelihood
`LOW` drops one level.

## New or pre-existing

A finding is new if it covers a line the pull request (or, from the command line, the changes since
`--base`) added or changed.

A finding on untouched lines is new too when the file didn't have it before. The base version of a
changed file is scanned too, so editing one line can't slip in a finding on another. Only files with a
finding on untouched lines need it, so most pull requests are scanned once.

Such a finding is pre-existing only if the base version had the same rule and line text on the line it
came from, found through the diff. Lines added above it move it, and it stays pre-existing. The same text
on another line of the base version is a different finding.

For example, changing `const cmd = 'ls'` to `'ls ' + req.query.dir` makes the untouched `exec(cmd)` below
it a new P1.

Pre-existing findings are still reported, as notices.

Edge cases:

- No diff for a file (too large or unreadable): every finding in it counts as new.
- Base version missing, over 1 MiB or not scannable: every finding in the file counts as new.
- Renamed with no changes: unchanged.
- Renamed or copied from test code to runtime code: every finding counts as new, since its priority went
  up.

A full scan, with no `--base`, has no diff, so every finding counts as new.

## Test code

Test code follows pytest, Django and JavaScript naming:

- Any language: a `test` or `tests` folder, or a `test_*` name.
- Python also: `*_test.py` or `tests.py`.
- JavaScript and TypeScript also: a `__tests__`, `spec`, `specs`, `e2e` or `cypress` folder, or a
  `*.test.*` or `*.spec.*` name.

`conftest.py` always counts as runtime code.

## Gate

The gate fails only when a finding is both new and P1. Scanner errors and partial results also fail it.
Only a complete scan can pass.

## Limits

The README's [Scope and limits](../README.md#scope-and-limits) say what triage can't see: rules match
within one file, new is judged file by file, and size limits fail closed.
