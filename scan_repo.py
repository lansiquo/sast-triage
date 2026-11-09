"""Full-repository scan: every supported source file, the service-owned rules, the same triage and gate.

Without --base there is no diff, so every finding counts as new. With
--base REF, only the source files changed since REF are scanned, and a finding
is new when it covers a line they added or changed, as for a pull request.
The scanned project is only read and parsed by Semgrep: never executed,
imported or installed, and its own Semgrep rules and ignore files are not used.

Exit status: 0 when the gate passes, 1 when it fails (a new P1 finding),
2 on a usage or scanner error (no result is issued).
"""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from analyzers.semgrep_runner import SemgrepInvocationError, run_semgrep, summarize_findings
from analyzers.triage import added_lines, gate, is_source_path, is_test_path, triage
from trusted_rules import OFFLINE_RULESET

# Dependencies, build output and VCS metadata. The runner never scans the
# virtualenv and cache folders either, so listing a file there would fail the scan.
EXCLUDED_DIRS = ('.git', 'node_modules', 'vendor', 'dist', 'build', 'coverage',
                 '.hg', '.svn', '.venv', 'venv', '__pycache__')
MINIFIED = re.compile(r'\.min\.[cm]?js$')
MAX_FILE_BYTES = 1024 * 1024   # the runner's per-file limit
RULE_COUNT = len(re.findall(r'^  - id: ', OFFLINE_RULESET, re.M))
PASS, FAIL, ERROR = 0, 1, 2


def scannable(path: str) -> bool:
    """A supported source file outside the excluded folders, and not minified."""
    parts = path.split('/')
    return is_source_path(parts[-1]) and not MINIFIED.search(parts[-1]) and not any(p in EXCLUDED_DIRS for p in parts[:-1])


class DiffError(Exception):
    """git could not produce the diff against the base."""


def git(root: Path, *args: str) -> str:
    """Run git in the project without external diff drivers, text conversion or pagers."""
    try:
        # The project's own git config must not run anything: no fsmonitor hook, no external diff.
        result = subprocess.run(['git', '-C', str(root), '-c', 'core.quotepath=off', '-c', 'core.fsmonitor=',
                                 '-c', 'diff.external=', *args],
                                capture_output=True, text=True, timeout=120,
                                env={**os.environ, 'GIT_PAGER': 'cat', 'GIT_EXTERNAL_DIFF': ''})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiffError(f'git failed: {error}') from error
    if result.returncode != 0:
        raise DiffError(result.stderr.strip() or f'git {args[0]} failed')
    return result.stdout


def changes_since(root: Path, base: str):
    """Map each source file changed since `base` (and not deleted) to the lines it added or changed.

    Uses the merge base of `base` and HEAD, the way a pull request is compared,
    and the same rules as the pull request path: a rename with no edits changed
    nothing, a move from test code to runtime code counts as entirely new, and
    a diff that does not parse is unknown (None), so every finding in it is new.
    """
    if base.startswith('-'):
        raise DiffError(f'invalid base: {base}')
    git(root, 'rev-parse', '--verify', '--quiet', f'{base}^{{commit}}')
    spec = f'{base}...HEAD'
    fields = git(root, 'diff', '--relative', '--name-status', '-z', '-M', '--no-ext-diff', '--no-textconv', spec).split('\0')
    changed = {}
    i = 0
    while i < len(fields) - 1:
        status = fields[i]
        if status.startswith(('R', 'C')):
            old, path = fields[i + 1], fields[i + 2]
            i += 3
        else:
            old, path = None, fields[i + 1]
            i += 2
        if status.startswith('D') or not scannable(path):
            continue
        if old is not None and is_test_path(old) and not is_test_path(path):
            changed[path] = None
            continue
        paths = [old, path] if old is not None else [path]
        patch = git(root, 'diff', '--relative', '-M', '--unified=0', '--no-color', '--no-ext-diff', '--no-textconv', spec, '--', *paths)
        hunks = patch.find('\n@@')
        if hunks == -1:
            changed[path] = set() if status.startswith('R') and 'Binary files' not in patch else None
        else:
            changed[path] = added_lines(patch[hunks + 1:])
    return changed


def source_files(root: Path):
    """Repository-relative paths of every supported source file, sorted. Symbolic links are skipped."""
    found = []
    for directory, folders, files in os.walk(root):   # does not follow linked folders
        folders[:] = [name for name in folders if name not in EXCLUDED_DIRS]
        for name in files:
            path = Path(directory, name)
            if is_source_path(name) and not MINIFIED.search(name) and not path.is_symlink() and path.is_file():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def print_summary(title, findings, conclusion, base=None):
    """One line per triaged finding, then the Check Run's Markdown summary with the gate result."""
    print(f'\n{title}: {conclusion.upper()}')
    for f in findings:
        label = 'new' if f['new'] else 'pre-existing'
        print(f"  [{f['priority']}, {label}] {f['path']}:{f['start_line']}  {f['rule_id']}")
    print(markdown(findings, base))


def markdown(findings, base=None):
    """The Check Run's Markdown summary, with the "new" legend worded for this kind of scan."""
    meaning = f'New: on lines changed since {base}.' if base else 'New: every finding in a full scan.'
    return summarize_findings(findings)[1].replace('New: on lines this pull request added or changed.', meaning)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('directory', type=Path, help='project to scan')
    parser.add_argument('--json', action='store_true', help='print the triaged findings as JSON instead of the report')
    parser.add_argument('--base', metavar='REF',
                        help='scan only the files changed since this git ref (for example origin/main); '
                             'findings on lines they did not change are pre-existing')
    parser.add_argument('--markdown', type=Path, metavar='FILE', help='also write the Markdown summary to FILE')
    parser.add_argument('--timeout', type=int, default=300, metavar='SECONDS',
                        help='scanner time limit (default: 300)')
    args = parser.parse_args(argv)
    if not args.directory.is_dir():
        parser.error(f'not a directory: {args.directory}')
    root = args.directory.resolve()
    if args.base:
        try:
            changed = changes_since(root, args.base)
        except DiffError as error:
            print(f'error: cannot diff against {args.base}, no result issued.\n{error}', file=sys.stderr)
            return ERROR
        files = sorted(p for p in changed if not (root / p).is_symlink())
        missing = [p for p in files if not (root / p).is_file()]
        if missing:
            print('error: changed files are missing from the working tree, no result issued: ' + ', '.join(missing),
                  file=sys.stderr)
            return ERROR
    else:
        files = source_files(root)
        changed = dict.fromkeys(files)   # no diff: every file's changes are unknown, so every finding is new
    too_large = [name for name in files if (root / name).stat().st_size > MAX_FILE_BYTES]
    if too_large:
        print('error: over the 1 MiB per-file scan limit, no result issued: ' + ', '.join(too_large), file=sys.stderr)
        return ERROR

    findings = []
    if files:
        with tempfile.TemporaryDirectory(prefix='prsec_scan_repo_') as temporary:
            config = Path(temporary) / 'rules.yaml'
            config.write_text(OFFLINE_RULESET)
            try:
                findings = run_semgrep(files, str(root), config=str(config), timeout_s=args.timeout)
            except (SemgrepInvocationError, ValueError, RuntimeError, OSError) as error:
                print(f'error: scan incomplete, no result issued.\n{error}', file=sys.stderr)
                return ERROR
    findings = triage(findings, changed)
    conclusion = gate(findings) if files else 'neutral'

    if args.markdown:
        args.markdown.write_text(markdown(findings, args.base) + '\n')
    scan = f'changes since {args.base}' if args.base else 'full: every finding counts as new'
    if args.json:
        print(json.dumps({'directory': str(args.directory), 'scan': scan, 'base': args.base,
                          'files_scanned': len(files), 'files': files, 'rules': RULE_COUNT,
                          'conclusion': conclusion, 'counts': summarize_findings(findings)[0],
                          'findings': findings}, indent=2))
    else:
        if args.base:
            print(f'sast-triage scan of {args.directory}, changes since {args.base}')
            print('A finding is new when it covers a line changed since the base; only a new P1 fails.')
            print(f'{len(files)} changed Python, JavaScript and TypeScript files, {RULE_COUNT} service-owned rules.')
            title = f'Changes since {args.base} ({len(files)} files)'
        else:
            print(f'sast-triage full scan of {args.directory}')
            print('Full scan: every finding counts as new (there is no diff).')
            print(f'{len(files)} Python, JavaScript and TypeScript files, {RULE_COUNT} service-owned rules.')
            title = f'Full scan ({len(files)} files)'
        print(f'Skipped: {", ".join(EXCLUDED_DIRS)} folders and minified *.min.js files.')
        if files:
            print_summary(title, findings, conclusion, args.base)
        else:
            print('\nNo supported Python, JavaScript or TypeScript files to scan.')
    return FAIL if conclusion == 'failure' else PASS


if __name__ == '__main__':
    sys.exit(main())
