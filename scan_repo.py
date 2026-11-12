"""Full-repository scan: every supported source file, the service-owned rules, the same triage and gate.

Without --base there is no diff, so every finding counts as new. With
--base REF, only the source files changed since REF are scanned, and a finding
is new when it covers a line they added or changed, or when the version of the
file before those changes did not have it, as for a pull request.
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
from collections import Counter
from pathlib import Path

from analyzers.semgrep_runner import (NEW_LEGEND, SemgrepInvocationError, _annotation_level, add_fingerprints,
                                      ascii_name, is_utf8_name, run_semgrep, summarize_findings,
                                      to_github_annotations)
from analyzers.triage import (NOT_IN_BASE, added_lines, baseline_counts, gate, is_source_path, is_test_path,
                              needs_base, triage)
from trusted_rules import OFFLINE_RULESET

# Dependencies, build output and VCS metadata. The runner never scans the
# virtualenv and cache folders either, so listing a file there would fail the scan.
EXCLUDED_DIRS = ('.git', 'node_modules', 'vendor', 'dist', 'build', 'coverage',
                 '.hg', '.svn', '.venv', 'venv', '__pycache__')
# Changed files (--base) are scanned in build, dist, vendor and coverage folders too, as the GitHub
# App scans them, so a change can't hide code there. Folders the scanner refuses, installed
# dependencies and minified files are still left out, and the changed files there are listed.
CHANGED_EXCLUDED_DIRS = ('.git', '.hg', '.svn', '.venv', 'venv', '__pycache__', 'node_modules')
MINIFIED = re.compile(r'\.min\.[cm]?js$')
MAX_FILE_BYTES = 1024 * 1024   # the runner's per-file limit
RULE_COUNT = len(re.findall(r'^  - id: ', OFFLINE_RULESET, re.M))
PASS, FAIL, ERROR = 0, 1, 2


def scannable(path: str, excluded=EXCLUDED_DIRS) -> bool:
    """A supported source file outside the excluded folders, and not minified."""
    parts = path.split('/')
    return is_source_path(parts[-1]) and not MINIFIED.search(parts[-1]) and not any(p in excluded for p in parts[:-1])


class DiffError(Exception):
    """git could not produce the diff against the base. `status` is git's exit status when it ran and failed."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def git(root: Path, *args: str, binary: bool = False):
    """Run git in the project without external diff drivers, text conversion or pagers.

    Returns its output as text, or as bytes with binary=True (for file contents and the -z list of names).
    """
    try:
        # The project's own git config must not run anything: no fsmonitor hook, no external diff.
        result = subprocess.run(['git', '-C', str(root), '-c', 'core.quotepath=off', '-c', 'core.fsmonitor=',
                                 '-c', 'diff.external=', *args],
                                capture_output=True, text=not binary, timeout=120,
                                env={**os.environ, 'GIT_PAGER': 'cat', 'GIT_EXTERNAL_DIFF': ''})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiffError(f'git failed: {error}') from error
    except UnicodeDecodeError as error:   # text output is decoded strictly, so it never reaches the scan garbled
        raise DiffError(f'git {args[0]} output is not valid UTF-8') from error
    if result.returncode != 0:
        stderr = result.stderr.decode('utf-8', 'replace') if binary else result.stderr
        raise DiffError(stderr.strip() or f'git {args[0]} failed', result.returncode)
    return result.stdout


def changes_since(root: Path, base: str):
    """Map each source file changed since `base` (and not deleted) to the lines it added or changed.

    Uses the merge base of `base` and HEAD, the way a pull request is compared,
    and the same rules as the pull request path: a rename with no edits changed
    nothing, a move from test code to runtime code counts as entirely new, and
    a diff that does not parse is unknown (None), so every finding in it is new.

    Also returns each file's path in the base (its old name after a rename;
    a file the changes added has none), and the changed source files that are
    not scanned because they are in a folder in CHANGED_EXCLUDED_DIRS or minified.
    """
    if base.startswith('-'):
        raise DiffError(f'invalid base: {base}')
    # Each lookup exits with status 1 when the history it needs is not in the checkout, most often
    # a shallow clone. Any other git failure keeps git's own message.
    try:
        git(root, 'rev-parse', '--verify', '--quiet', f'{base}^{{commit}}')
    except DiffError as error:
        if error.status != 1:
            raise
        raise DiffError(f'{base} is not a commit in this checkout. Check the ref name, or fetch the base branch '
                        'first (`git fetch`); in GitHub Actions, check out with `fetch-depth: 0`.') from error
    try:
        git(root, 'merge-base', base, 'HEAD')
    except DiffError as error:
        if error.status != 1:
            raise
        raise DiffError(f'no merge base was found for {base} and HEAD. A shallow clone leaves out the history '
                        'they share: fetch it with `git fetch --unshallow`, or in GitHub Actions check out with '
                        '`fetch-depth: 0`.') from error
    spec = f'{base}...HEAD'
    # The -z list is bytes, not text: each name is taken exactly as git lists it, or the scan stops.
    listing = git(root, 'diff', '--relative', '--name-status', '-z', '-M', '--no-ext-diff', '--no-textconv', spec,
                  binary=True)
    try:
        fields = listing.decode('utf-8').split('\0')
    except UnicodeDecodeError:
        names = []
        for name in listing.split(b'\0'):
            try:
                name.decode('utf-8')
            except UnicodeDecodeError:
                names.append(ascii_name(name))
        raise DiffError('changed file names that are not valid UTF-8 cannot be scanned: ' + ', '.join(names)) from None
    changed = {}
    previous = {}
    skipped = []
    i = 0
    while i < len(fields) - 1:
        status = fields[i]
        if status.startswith(('R', 'C')):
            old, path = fields[i + 1], fields[i + 2]
            i += 3
        else:
            old, path = None, fields[i + 1]
            i += 2
        if status.startswith('D'):
            continue
        if not scannable(path, CHANGED_EXCLUDED_DIRS):
            if is_source_path(path.split('/')[-1]):
                skipped.append(path)
            continue
        if not status.startswith('A'):
            previous[path] = old if old is not None else path
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
    return changed, previous, sorted(skipped)


def base_findings(root: Path, base: str, previous: dict, config: str, timeout: int):
    """Scan the base version of each file in `previous` and count its findings, keyed by the head path.

    The base version is the file at the merge base of `base` and HEAD, read from
    git and scanned in a temporary folder. A file that is missing there, too large
    or unsafe to place is left out, so its findings count as new. Returns None when
    the base versions cannot be scanned at all.
    """
    if not previous:
        return {}
    merge_base = git(root, 'merge-base', base, 'HEAD').strip()
    baseline = {}
    with tempfile.TemporaryDirectory(prefix='prsec_scan_base_') as temporary:
        staging = Path(temporary).resolve()
        staged = {}   # base path -> the head paths that came from it
        for path, old in sorted(previous.items()):
            target = (staging / old).resolve()
            if not is_source_path(old) or not target.is_relative_to(staging) or target == staging:
                continue
            try:
                content = git(root, 'show', f'{merge_base}:./{old}', binary=True)
            except DiffError:
                continue
            if len(content) > MAX_FILE_BYTES:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            staged.setdefault(old, []).append(path)
        if staged:
            try:
                found = add_fingerprints(run_semgrep(sorted(staged), str(staging), config=config, timeout_s=timeout),
                                         str(staging))
            except (SemgrepInvocationError, ValueError, RuntimeError, OSError):
                return None
            counts = baseline_counts(found)
            for old, paths in staged.items():
                for path in paths:
                    baseline[path] = Counter(counts.get(old, Counter()))
    return baseline


def source_files(root: Path):
    """Repository-relative paths of every supported source file, sorted. Symbolic links are skipped."""
    def unreadable(error):
        raise error   # a folder that can't be listed must not be skipped silently

    found = []
    for directory, folders, files in os.walk(root, onerror=unreadable):   # does not follow linked folders
        folders[:] = [name for name in folders if name not in EXCLUDED_DIRS]
        for name in files:
            path = Path(directory, name)
            if is_source_path(name) and not MINIFIED.search(name) and not path.is_symlink() and path.is_file():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


# Control characters, and the two Unicode characters that end a line: all that can break a printed line.
LINE_BREAKING = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')


def log_safe(text, lines=False, json_text=False):
    """Text that can hold file names of the scanned project, made safe to print where a CI runner reads it.

    GitHub Actions takes a workflow command from an output line that starts with `::name::`, and from
    `##[name]` anywhere in a line. So control characters, line breaks included, become `?` as in
    skipped_note(), and `##[` becomes `#?[`. Every line the scan prints starts with its own fixed text,
    so a name that cannot break the line cannot start one. Other text comes back unchanged.

    lines=True is for an error message of several lines (git's, the scanner's): its line feeds stay,
    and a line that would start with `::` starts with `?` instead.
    json_text=True is for JSON, which has escaped the control characters already: `##[` is written as
    `#\\u0023[`, which decodes to the same string.
    """
    if json_text:
        return text.replace('##[', '#\\u0023[')
    if lines:
        return '\n'.join('?' + line if line.lstrip().startswith('::') else line
                         for line in map(log_safe, text.split('\n')))
    return LINE_BREAKING.sub('?', text).replace('##[', '#?[')


def print_summary(title, findings, conclusion, base=None):
    """One line per triaged finding, then the Check Run's Markdown summary with the gate result."""
    print(f'\n{title}: {conclusion.upper()}')
    for f in findings:
        label = 'new' if f['new'] else 'pre-existing'
        note = '  (line unchanged; not in the base version)' if f.get('new_because') == NOT_IN_BASE else ''
        print(log_safe(f"  [{f['priority']}, {label}] {f['path']}:{f['start_line']}  {f['rule_id']}{note}"))
    print(markdown([{**f, 'path': log_safe(f['path'])} for f in findings], base))


def markdown(findings, base=None):
    """The Check Run's Markdown summary, with the "new" legend worded for this kind of scan."""
    meaning = (f'New: on lines changed since {base}, or not in the file before those changes.' if base
               else 'New: every finding in a full scan.')
    return summarize_findings(findings)[1].replace(NEW_LEGEND, meaning)


# Check Run annotation level (analyzers.semgrep_runner) -> SARIF result level.
SARIF_LEVEL = {'failure': 'error', 'warning': 'warning', 'notice': 'note'}


def sarif_document(findings):
    """A SARIF 2.1.0 document: one run of the service-owned rules, one result per triaged finding.

    The results mirror the --json findings in the same order; each reported rule id
    appears once in tool.driver.rules. The result level follows the Check Run
    annotations (new P1 is an error, new P2 a warning, everything else a note).
    """
    rule_ids = list(dict.fromkeys(f['rule_id'] for f in findings))
    results = []
    for f in findings:
        result = {
            'ruleId': f['rule_id'],
            'level': SARIF_LEVEL[_annotation_level(f)],
            'message': {'text': f.get('message') or f.get('title') or f['rule_id']},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': f['path']},
                'region': {'startLine': f['start_line'], 'endLine': f['end_line']}}}],
            'properties': {'priority': f['priority'], 'new': f['new'],
                           'new_because': f['new_because'], 'cwe': f.get('cwe')},
        }
        if f.get('fingerprint'):
            result['partialFingerprints'] = {'fingerprint': f['fingerprint']}
        results.append(result)
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'sast-triage',
                                      'rules': [{'id': rule_id} for rule_id in rule_ids]}},
                  'results': results}],
    }


def write_sarif(path: Path, document):
    """Write the SARIF document atomically, so a failed write leaves no partial artifact.

    The document is written to a temporary file in the destination's directory and
    renamed into place only once it is complete. Any OSError (a missing or unwritable
    directory) propagates with the destination untouched, and the temporary is removed.
    """
    text = json.dumps(document, indent=2) + '\n'
    handle = tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.sarif_', suffix='.tmp',
                                         delete=False, encoding='utf-8')
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(text)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


MAX_ANNOTATIONS = 200   # as on the GitHub App's Check Run
# Check Run annotation level (analyzers.semgrep_runner) -> GitHub Actions workflow command.
ANNOTATION_COMMAND = {'failure': 'error', 'warning': 'warning', 'notice': 'notice'}


def workflow_commands(findings, directory):
    """GitHub Actions workflow commands that annotate the findings: the Check Run's annotations, for a runner.

    One line per finding, for the first MAX_ANNOTATIONS findings in the order given (P1 first), each
    with the level and title of its Check Run annotation: `::error` for a new P1, `::warning` for a new
    P2, `::notice` otherwise. `file` is the scanned directory joined with the finding's path, which
    names the file from the workspace when the scan runs there, as the Action's does.

    Every value is escaped the way the runner unescapes it: `%` first, then carriage return and line
    feed, and in a property also `:` and `,`. So no value can end its line, end the properties or add
    one, and each line is exactly one command. log_safe() then treats the line like every other line.
    """
    def escaped(value, is_property=True):
        value = str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        return value.replace(':', '%3A').replace(',', '%2C') if is_property else value

    commands = []
    shown = findings[:MAX_ANNOTATIONS]
    for f, annotation in zip(shown, to_github_annotations(shown)):
        properties = {'file': (directory / f['path']).as_posix(), 'line': annotation['start_line'],
                      'endLine': annotation['end_line'], 'title': annotation['title']}
        message = f"{annotation['message']}\nRule: {f['rule_id']}" + (f", {f['cwe']}" if f.get('cwe') else '')
        commands.append(log_safe(f"::{ANNOTATION_COMMAND[annotation['annotation_level']]} "
                                 + ','.join(f'{name}={escaped(value)}' for name, value in properties.items())
                                 + '::' + escaped(message, is_property=False)))
    return commands


def skipped_note(skipped):
    """For the Markdown summary: the changed files a --base scan left out, so none are skipped silently."""
    if not skipped:
        return ''
    shown = ', '.join('`' + re.sub(r'[\x00-\x1f`|]', '?', path) + '`' for path in skipped[:10])
    more = f' and {len(skipped) - 10} more' if len(skipped) > 10 else ''
    return f'\n\nSkipped changed files (dependency or tool folders, or minified): {shown}{more}.'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('directory', type=Path, help='project to scan')
    parser.add_argument('--json', action='store_true', help='print the triaged findings as JSON instead of the report')
    parser.add_argument('--base', metavar='REF',
                        help='scan only the files changed since this git ref (for example origin/main); '
                             'findings on lines they did not change are pre-existing')
    parser.add_argument('--markdown', type=Path, metavar='FILE', help='also write the Markdown summary to FILE')
    parser.add_argument('--sarif', type=Path, metavar='FILE',
                        help='also write the findings as a SARIF 2.1.0 file')
    parser.add_argument('--timeout', type=int, default=300, metavar='SECONDS',
                        help='scanner time limit (default: 300)')
    parser.add_argument('--github-annotations', action='store_true',
                        help='after the report, also print one GitHub Actions workflow command per finding '
                             '(at most 200), which GitHub shows as annotations; not with --json')
    args = parser.parse_args(argv)
    if args.github_annotations and args.json:
        parser.error('--github-annotations cannot be used with --json: the commands would not be JSON')
    if not args.directory.is_dir():
        parser.error(f'not a directory: {args.directory}')
    if args.base == '':   # every check below reads an empty ref as "no --base", which would run a full scan
        parser.error('--base needs a git ref; leave out --base for a full scan')
    root = args.directory.resolve()
    previous, skipped = {}, []
    if args.base:
        try:
            changed, previous, skipped = changes_since(root, args.base)
        except DiffError as error:
            print(f'error: cannot diff against {args.base}, no result issued.\n{log_safe(str(error), lines=True)}',
                  file=sys.stderr)
            return ERROR
        files = sorted(p for p in changed if not (root / p).is_symlink())
        missing = [p for p in files if not (root / p).is_file()]
        if missing:
            print('error: changed files are missing from the working tree, no result issued: '
                  + log_safe(', '.join(missing)), file=sys.stderr)
            return ERROR
    else:
        try:
            files = source_files(root)
        except OSError as error:
            print(f'error: cannot list the project files, no result issued.\n{log_safe(str(error), lines=True)}',
                  file=sys.stderr)
            return ERROR
        changed = dict.fromkeys(files)   # no diff: every file's changes are unknown, so every finding is new
    # Semgrep lists a file with such a name as scanned without matching a rule against it.
    not_utf8 = [ascii_name(name) for name in files if not is_utf8_name(name)]
    if not_utf8:
        print('error: file names that are not valid UTF-8 cannot be scanned, no result issued: ' + ', '.join(not_utf8),
              file=sys.stderr)
        return ERROR
    too_large = [name for name in files if (root / name).stat().st_size > MAX_FILE_BYTES]
    if too_large:
        print('error: over the 1 MiB per-file scan limit, no result issued: ' + log_safe(', '.join(too_large)),
              file=sys.stderr)
        return ERROR

    findings = []
    baseline = None   # full scan: there is no base version, and every finding is new anyway
    if files:
        with tempfile.TemporaryDirectory(prefix='prsec_scan_repo_') as temporary:
            config = Path(temporary) / 'rules.yaml'
            config.write_text(OFFLINE_RULESET)
            try:
                findings = add_fingerprints(run_semgrep(files, str(root), config=str(config), timeout_s=args.timeout),
                                            str(root))
            except (SemgrepInvocationError, ValueError, RuntimeError, OSError) as error:
                print(f'error: scan incomplete, no result issued.\n{log_safe(str(error), lines=True)}',
                      file=sys.stderr)
                return ERROR
            if args.base:
                # Only files with a finding on untouched lines need their base version.
                try:
                    baseline = base_findings(root, args.base, {p: previous[p] for p in needs_base(findings, changed)
                                                               if p in previous}, str(config), args.timeout)
                except DiffError as error:
                    print(f'error: cannot read the base versions from {args.base}, no result issued.\n'
                          f'{log_safe(str(error), lines=True)}', file=sys.stderr)
                    return ERROR
                if baseline is None:
                    print('warning: the base versions of the changed files could not be scanned, '
                          'so every finding counts as new.', file=sys.stderr)
                    baseline = {}
    findings = triage(findings, changed, baseline)
    conclusion = gate(findings) if files else 'neutral'

    if args.markdown:
        args.markdown.write_text(markdown(findings, args.base) + skipped_note(skipped) + '\n')
    if args.sarif:
        try:
            write_sarif(args.sarif, sarif_document(findings))
        except OSError as error:
            print(f'error: could not write the SARIF file {args.sarif}, no result issued.\n{error}',
                  file=sys.stderr)
            return ERROR
    scan = f'changes since {args.base}' if args.base else 'full: every finding counts as new'
    if args.json:
        print(log_safe(json.dumps({'directory': str(args.directory), 'scan': scan, 'base': args.base,
                                   'files_scanned': len(files), 'files': files, 'rules': RULE_COUNT,
                                   'skipped_changed_files': skipped, 'conclusion': conclusion,
                                   'counts': summarize_findings(findings)[0], 'findings': findings}, indent=2),
                       json_text=True))
    else:
        if args.base:
            print(f'sast-triage scan of {args.directory}, changes since {args.base}')
            print('A finding is new when it covers a line changed since the base, or was not in the file before; '
                  'only a new P1 fails.')
            print(f'{len(files)} changed Python, JavaScript and TypeScript files, {RULE_COUNT} service-owned rules.')
            title = f'Changes since {args.base} ({len(files)} files)'
        else:
            print(f'sast-triage full scan of {args.directory}')
            print('Full scan: every finding counts as new (there is no diff).')
            print(f'{len(files)} Python, JavaScript and TypeScript files, {RULE_COUNT} service-owned rules.')
            title = f'Full scan ({len(files)} files)'
        print(f'Skipped: {", ".join(CHANGED_EXCLUDED_DIRS if args.base else EXCLUDED_DIRS)} folders and minified '
              '*.min.js files.')
        if skipped:
            print(log_safe(f'Skipped changed files: {", ".join(skipped)}'))
        if files:
            print_summary(title, findings, conclusion, args.base)
        else:
            print('\nNo supported Python, JavaScript or TypeScript files to scan.')
        if args.github_annotations:
            for command in workflow_commands(findings, args.directory):
                print(command)
    return FAIL if conclusion == 'failure' else PASS


if __name__ == '__main__':
    sys.exit(main())
