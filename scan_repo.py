"""Full-repository scan: every supported source file, the service-owned rules, the same triage and gate.

There is no diff, so every finding counts as new. The scanned project is only
read and parsed by Semgrep: never executed, imported or installed, and its own
Semgrep rules and ignore files are not used.

Exit status: 0 when the gate passes, 1 when it fails (a new P1 finding),
2 on a usage or scanner error (no result is issued).
"""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from analyzers.semgrep_runner import SemgrepInvocationError, run_semgrep, summarize_findings
from analyzers.triage import gate, is_source_path, triage
from demo import print_summary
from trusted_rules import OFFLINE_RULESET

# Dependencies, build output and VCS metadata. The runner never scans the
# virtualenv and cache folders either, so listing a file there would fail the scan.
EXCLUDED_DIRS = ('.git', 'node_modules', 'vendor', 'dist', 'build', 'coverage',
                 '.hg', '.svn', '.venv', 'venv', '__pycache__')
MINIFIED = re.compile(r'\.min\.[cm]?js$')
MAX_FILE_BYTES = 1024 * 1024   # the runner's per-file limit
RULE_COUNT = len(re.findall(r'^  - id: ', OFFLINE_RULESET, re.M))
PASS, FAIL, ERROR = 0, 1, 2


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('directory', type=Path, help='project to scan')
    parser.add_argument('--json', action='store_true', help='print the triaged findings as JSON instead of the report')
    parser.add_argument('--timeout', type=int, default=300, metavar='SECONDS',
                        help='scanner time limit (default: 300)')
    args = parser.parse_args(argv)
    if not args.directory.is_dir():
        parser.error(f'not a directory: {args.directory}')
    root = args.directory.resolve()
    files = source_files(root)
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
    # No diff: every file's changes are unknown (None), so every finding is new.
    findings = triage(findings, dict.fromkeys(files))
    conclusion = gate(findings) if files else 'neutral'

    if args.json:
        print(json.dumps({'directory': str(args.directory), 'scan': 'full: every finding counts as new',
                          'files_scanned': len(files), 'files': files, 'rules': RULE_COUNT,
                          'conclusion': conclusion, 'counts': summarize_findings(findings)[0],
                          'findings': findings}, indent=2))
    else:
        print(f'sast-triage full scan of {args.directory}')
        print('Full scan: every finding counts as new (there is no diff).')
        print(f'{len(files)} Python, JavaScript and TypeScript files, {RULE_COUNT} service-owned rules.')
        print(f'Skipped: {", ".join(EXCLUDED_DIRS)} folders and minified *.min.js files.')
        if files:
            print_summary(f'Full scan ({len(files)} files)', findings, conclusion)
        else:
            print('\nNo supported Python, JavaScript or TypeScript files to scan.')
    return FAIL if conclusion == 'failure' else PASS


if __name__ == '__main__':
    sys.exit(main())
