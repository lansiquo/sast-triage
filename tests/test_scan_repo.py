"""Full-repository scan CLI: real Semgrep on a small fixture tree that is written, scanned and never executed."""
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import scan_repo
from analyzers import semgrep_runner as runner

ROOT = Path(__file__).resolve().parent.parent

# path: source. Each file would leave a marker if anything ever ran it.
PROJECT = {
    'server.js': "require('fs').writeFileSync('EXECUTED', '');\nconst total = eval(req.body.preTax);",
    'routes/redirect.ts': 'export const go = (req, res) => res.redirect(req.query.url);',
    'tools/report.py': "open('EXECUTED', 'w')\nimport os\nos.popen('ls')",
    'test/routes.test.js': 'eval(fixture);',          # high severity in test code: P2
    'src/ok.mjs': 'export const add = (a, b) => a + b;',
    # Never listed or scanned.
    'node_modules/pkg/index.js': 'eval(code);',
    'web/vendor/lib.js': 'eval(code);',
    'dist/bundle.js': 'eval(code);',
    'build/out.js': 'eval(code);',
    'coverage/lcov-report/sorter.js': 'eval(code);',
    '.git/hooks/pre-commit.js': 'eval(code);',
    '.venv/lib/site.py': 'eval(code)',
    'public/app.min.js': 'eval(code);',
    'README.md': 'eval(code);',
}
SCANNED = ['routes/redirect.ts', 'server.js', 'src/ok.mjs', 'test/routes.test.js', 'tools/report.py']


def project(tmp_path, files=PROJECT):
    for name, source in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(source + '\n')
    return tmp_path


@pytest.fixture(autouse=True)
def local_scanner(monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')


def test_json_lists_every_source_file_outside_excluded_folders_and_triages_them_all_as_new(tmp_path, capsys):
    root = project(tmp_path)
    assert scan_repo.main([str(root), '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == SCANNED and report['files_scanned'] == 5
    assert report['conclusion'] == 'failure' and report['rules'] == 41
    assert [(f['priority'], f['new'], f['path'], f['start_line'], f['rule_id']) for f in report['findings']] == [
        ('P1', True, 'server.js', 2, 'js-dangerous-eval'),
        ('P1', True, 'tools/report.py', 3, 'py-os-popen'),
        ('P2', True, 'routes/redirect.ts', 1, 'js-open-redirect'),
        ('P2', True, 'test/routes.test.js', 1, 'js-dangerous-eval'),
    ]
    assert report['counts'] == {'P1': {'new': 2, 'pre-existing': 0}, 'P2': {'new': 2, 'pre-existing': 0},
                                'P3': {'new': 0, 'pre-existing': 0}}
    assert not list(root.rglob('EXECUTED'))


def test_text_report_matches_the_pull_request_summary(tmp_path, capsys):
    assert scan_repo.main([str(project(tmp_path))]) == 1
    out = capsys.readouterr().out
    assert 'Full scan: every finding counts as new (there is no diff).' in out
    assert '5 Python, JavaScript and TypeScript files, 41 service-owned rules.' in out
    assert 'Full scan (5 files): FAILURE' in out
    assert '  [P1, new] server.js:2  js-dangerous-eval' in out
    assert '  [P2, new] test/routes.test.js:1  js-dangerous-eval' in out
    assert '**Gate: FAIL** — 2 new P1 findings:' in out and '| P2 | 2 | 0 |' in out
    assert 'New: every finding in a full scan.' in out and 'this pull request' not in out


def test_exit_status_is_zero_when_the_gate_passes(tmp_path, capsys):
    clean = project(tmp_path, {'app.js': 'res.redirect("/login");', 'test/a.test.js': 'eval(fixture);',
                               'node_modules/x.js': 'eval(code);'})
    assert scan_repo.main([str(clean)]) == 0      # a P2 in test code alone passes
    assert '**Gate: PASS**' in capsys.readouterr().out
    empty = tmp_path / 'docs'
    project(empty, {'README.md': 'nothing to scan'})
    assert scan_repo.main([str(empty), '--json']) == 0
    assert json.loads(capsys.readouterr().out)['conclusion'] == 'neutral'


def test_usage_and_scanner_errors_exit_with_two_and_issue_no_result(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as error:
        scan_repo.main([str(tmp_path / 'missing')])
    assert error.value.code == 2
    root = project(tmp_path / 'repo', {'app.js': 'eval(code);'})
    def broken(*a, **k):
        raise runner.SemgrepInvocationError(65, ['semgrep'], '', 'Scanner skipped requested source files')
    with monkeypatch.context() as m:
        m.setattr(scan_repo, 'run_semgrep', broken)
        assert scan_repo.main([str(root)]) == 2
    captured = capsys.readouterr()
    assert 'scan incomplete' in captured.err and 'Gate' not in captured.out
    (root / 'big.js').write_text('x' * (1024 * 1024 + 1))
    assert scan_repo.main([str(root)]) == 2
    assert 'big.js' in capsys.readouterr().err


def test_symbolic_links_are_not_followed(tmp_path, capsys):
    outside = project(tmp_path / 'outside', {'secret.js': 'eval(code);', 'lib/x.js': 'eval(code);'})
    root = project(tmp_path / 'repo', {'app.js': 'const a = 1;'})
    (root / 'linked.js').symlink_to(outside / 'secret.js')
    (root / 'linked').symlink_to(outside / 'lib')
    assert scan_repo.main([str(root), '--json']) == 0
    assert json.loads(capsys.readouterr().out)['files'] == ['app.js']


def test_command_line_on_the_make_check_fixture():
    # `make check` runs this command and expects exit status 1: the planted P1 fails the gate.
    result = subprocess.run([sys.executable, 'scan_repo.py', 'tests/fixtures/project'], cwd=ROOT,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 1, result.stderr
    assert '3 Python, JavaScript and TypeScript files, 41 service-owned rules.' in result.stdout
    assert '  [P1, new] server.js:2  js-dangerous-eval\n  [P2, new] __tests__/server.test.js:2  js-dangerous-eval\n' \
        in result.stdout


# --base: only files changed since a git ref are scanned, labelled as for a pull request.

def git(root, *args):
    subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, text=True,
                   env={'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
                        'GIT_COMMITTER_EMAIL': 't@t', 'HOME': str(root), 'PATH': '/usr/bin:/bin'})


def repository(tmp_path):
    """A base commit on main, then a feature branch that edits, adds and moves files."""
    project(tmp_path, {
        'src/legacy.py': "import os\nos.popen('ls')",                          # pre-existing P1, file edited
        'src/untouched.py': "import hashlib\nhashlib.md5(b'old')",              # never scanned
        'tests/test_cache.py': "import pickle\npickle.loads(b'')",             # moved into runtime code
        'web/app.js': 'const n = 1;',
    })
    git(tmp_path, 'init', '-q', '-b', 'main')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'base')
    git(tmp_path, 'switch', '-q', '-c', 'feature')
    project(tmp_path, {'src/legacy.py': "import os\nos.popen('ls')\n\nos.system(cmd)",
                       'web/app.js': 'const n = 1;\nconst total = eval(req.body.preTax);',
                       'docs/notes.md': 'eval(code)'})
    git(tmp_path, 'mv', 'tests/test_cache.py', 'src/cache.py')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'feature')
    return tmp_path


def test_base_scans_only_changed_files_and_labels_findings_like_a_pull_request(tmp_path, capsys):
    root = repository(tmp_path)
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['scan'] == 'changes since main' and report['files'] == ['src/cache.py', 'src/legacy.py', 'web/app.js']
    found = {(f['path'], f['start_line'], f['rule_id']): (f['priority'], f['new']) for f in report['findings']}
    assert found == {
        ('src/legacy.py', 4, 'py-os-system'): ('P1', True),
        ('src/legacy.py', 2, 'py-os-popen'): ('P1', False),               # untouched line: pre-existing
        ('web/app.js', 2, 'js-dangerous-eval'): ('P1', True),
        ('src/cache.py', 2, 'py-insecure-deserialization-pickle-loads'): ('P1', True),   # test -> runtime
    }


def test_base_passes_when_only_pre_existing_findings_remain(tmp_path, capsys):
    root = repository(tmp_path)
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'docs-only')
    project(root, {'src/legacy.py': "import os\nos.popen('ls')\n# reviewed"})
    git(root, 'commit', '-q', '-am', 'comment')
    assert scan_repo.main([str(root), '--base', 'main']) == 0
    out = capsys.readouterr().out
    assert '[P1, pre-existing] src/legacy.py:2  py-os-popen' in out and '**Gate: PASS**' in out
    assert 'New: on lines changed since main, or not in the file before those changes.' in out


def test_base_on_a_subfolder_uses_paths_relative_to_it(tmp_path, capsys):
    root = repository(tmp_path)
    assert scan_repo.main([str(root / 'web'), '--base', 'main', '--json']) == 1
    assert json.loads(capsys.readouterr().out)['files'] == ['app.js']


def test_markdown_file_holds_the_summary(tmp_path, capsys):
    root = repository(tmp_path)
    summary = tmp_path / 'summary.md'
    assert scan_repo.main([str(root), '--base', 'main', '--markdown', str(summary)]) == 1
    text = summary.read_text()
    assert text.startswith('### sast-triage — Semgrep summary') and '**Gate: FAIL** — 3 new P1 findings:' in text


@pytest.mark.parametrize('base', ['no-such-branch', '--output=x'])
def test_base_errors_exit_with_two_and_issue_no_result(tmp_path, capsys, base):
    root = repository(tmp_path)
    assert scan_repo.main([str(root), f'--base={base}']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'no result issued' in captured.err


@pytest.mark.parametrize('arguments', [['--base='], ['--base', '']])
def test_an_empty_base_is_a_usage_error_not_a_full_scan(tmp_path, capsys, arguments):
    # An empty --base (a CI variable left unset) once ran a full scan, which skips vendor/build/dist folders.
    root = repository(tmp_path)
    with pytest.raises(SystemExit) as error:
        scan_repo.main([str(root), *arguments, '--json'])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == '' and '--base' in captured.err


def test_base_outside_a_git_repository_exits_with_two(tmp_path, capsys):
    assert scan_repo.main([str(project(tmp_path, {'a.py': 'x = 1'})), '--base', 'main']) == 2
    assert 'no result issued' in capsys.readouterr().err


def test_the_command_line_scan_needs_none_of_the_web_service_packages():
    code = ('import sys, scan_repo; '
            "print(sorted(m for m in ('fastapi', 'uvicorn', 'jwt', 'pydantic', 'dotenv', 'app') if m in sys.modules))")
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.stdout.strip() == '[]', result.stderr
    required = (ROOT / 'requirements-cli.txt').read_text()
    assert 'semgrep==1.79.0' in required and 'fastapi' not in required


# Error and edge paths a user can hit from the command line.

def test_base_exits_with_two_when_git_cannot_run_or_times_out(tmp_path, monkeypatch, capsys):
    root = repository(tmp_path)
    for failure in (subprocess.TimeoutExpired(cmd='git', timeout=120), FileNotFoundError('git')):
        def broken(*a, failure=failure, **k):
            raise failure
        with monkeypatch.context() as m:
            m.setattr(scan_repo.subprocess, 'run', broken)
            assert scan_repo.main([str(root), '--base', 'main']) == 2
        captured = capsys.readouterr()
        assert captured.out == '' and 'cannot diff against main, no result issued' in captured.err
        assert 'git failed' in captured.err


def test_base_rename_without_edits_changes_nothing_but_a_change_with_no_line_diff_counts_as_new(tmp_path, capsys):
    root = repository(tmp_path)
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'move-only')
    git(root, 'mv', 'src/legacy.py', 'src/moved.py')          # same content, new name
    git(root, 'commit', '-q', '-m', 'move')
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 0   # its old P1 stays pre-existing
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == ['src/moved.py']
    assert [(f['path'], f['start_line'], f['rule_id'], f['priority'], f['new']) for f in report['findings']] == [
        ('src/moved.py', 2, 'py-os-popen', 'P1', False)]

    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'mode-only')
    (root / 'src/legacy.py').chmod(0o755)                       # changed, but git shows no line diff
    git(root, 'commit', '-q', '-am', 'mode')
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1   # unknown changes: every finding is new
    report = json.loads(capsys.readouterr().out)
    assert [(f['path'], f['priority'], f['new']) for f in report['findings']] == [('src/legacy.py', 'P1', True)]


def test_base_exits_with_two_when_a_changed_file_is_missing_from_the_working_tree(tmp_path, capsys):
    root = repository(tmp_path)
    (root / 'web/app.js').unlink()                              # committed on the branch, deleted locally
    assert scan_repo.main([str(root), '--base', 'main']) == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'changed files are missing from the working tree, no result issued: web/app.js' in captured.err


def test_text_report_says_so_when_there_is_nothing_to_scan(tmp_path, capsys):
    assert scan_repo.main([str(project(tmp_path, {'README.md': 'nothing to scan', 'docs/guide.md': 'eval(code)'}))]) == 0
    out = capsys.readouterr().out
    assert '0 Python, JavaScript and TypeScript files, 41 service-owned rules.' in out
    assert 'No supported Python, JavaScript or TypeScript files to scan.' in out and 'Gate' not in out


# --base: a finding on an untouched line is new when the base version of the file did not have it.

SERVER = ("const { exec } = require('child_process');\n"
          "module.exports = (req, res) => {\n"
          "  const cmd = %s;\n"
          "  exec(cmd, (e, out) => res.send(out));\n"
          "};")


def introduced_elsewhere(tmp_path, folder=''):
    """main runs a fixed command; the branch edits only the line above the exec call."""
    project(tmp_path, {f'{folder}server.js': SERVER % "'ls -la'", f'{folder}other.js': 'const n = 1;'})
    git(tmp_path, 'init', '-q', '-b', 'main')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'base')
    git(tmp_path, 'switch', '-q', '-c', 'feature')
    project(tmp_path, {f'{folder}server.js': SERVER % "'ls -la ' + req.query.dir"})
    git(tmp_path, 'commit', '-q', '-am', 'take the folder from the request')
    return tmp_path


def test_base_fails_when_a_change_on_another_line_introduces_the_finding(tmp_path, capsys):
    root = introduced_elsewhere(tmp_path)
    git(root, 'switch', '-q', 'main')
    assert scan_repo.main([str(root), '--json']) == 0             # the base alone is clean: the command is a constant
    assert json.loads(capsys.readouterr().out)['findings'] == []
    git(root, 'switch', '-q', 'feature')
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert [(f['path'], f['start_line'], f['rule_id'], f['priority'], f['new'], f['new_because'])
            for f in report['findings']] == [
        ('server.js', 4, 'js-child-process-exec', 'P1', True, 'not in the base version')]   # line 4 itself is unchanged
    assert scan_repo.main([str(root), '--base', 'main']) == 1
    out = capsys.readouterr().out
    assert '[P1, new] server.js:4  js-child-process-exec  (line unchanged; not in the base version)' in out
    assert 'A finding is new when it covers a line changed since the base, or was not in the file before' in out


def test_base_reads_base_versions_relative_to_a_scanned_subfolder(tmp_path, capsys):
    root = introduced_elsewhere(tmp_path, folder='svc/')
    assert scan_repo.main([str(root / 'svc'), '--base', 'main', '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert [(f['path'], f['new_because']) for f in report['findings']] == [('server.js', 'not in the base version')]


def test_base_counts_every_finding_as_new_when_the_base_versions_cannot_be_scanned(tmp_path, monkeypatch, capsys):
    root = repository(tmp_path)
    real, calls = scan_repo.run_semgrep, []

    def head_only(paths, repo_root, **options):
        calls.append(repo_root)
        if len(calls) > 1:                                        # the second scan is the base versions
            raise runner.SemgrepInvocationError(2, ['semgrep'], '', 'the old version does not parse')
        return real(paths, repo_root, **options)
    monkeypatch.setattr(scan_repo, 'run_semgrep', head_only)
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    captured = capsys.readouterr()
    assert 'could not be scanned, so every finding counts as new' in captured.err
    assert all(f['new'] for f in json.loads(captured.out)['findings']) and len(calls) == 2


def test_base_scans_once_when_every_finding_is_on_a_changed_line(tmp_path, monkeypatch, capsys):
    root = repository(tmp_path)
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'new-file')
    project(root, {'web/upload.js': 'const total = eval(req.body.total);'})       # a new file: every line added
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'upload')
    real, roots = scan_repo.run_semgrep, []
    monkeypatch.setattr(scan_repo, 'run_semgrep', lambda paths, repo_root, **o: roots.append(repo_root) or real(paths, repo_root, **o))
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    assert [(f['path'], f['new_because']) for f in json.loads(capsys.readouterr().out)['findings']] == [
        ('web/upload.js', 'changed lines')]
    assert len(roots) == 1                                        # no base version was scanned


def test_base_scans_changed_files_in_build_dist_vendor_and_coverage_folders(tmp_path, capsys):
    # The GitHub App scans these, so a change must not pass by putting code in such a folder.
    project(tmp_path, {'app/main.py': 'x = 1'})
    git(tmp_path, 'init', '-q', '-b', 'main')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'base')
    git(tmp_path, 'switch', '-q', '-c', 'feature')
    project(tmp_path, {'app/build/handler.py': 'import os\nos.system(cmd)', 'web/vendor/lib.js': 'eval(code);',
                       'dist/bundle.js': 'eval(code);', 'coverage/report.js': 'eval(code);',
                       'node_modules/pkg/index.js': 'eval(code);', 'public/app.min.js': 'eval(code);',
                       'docs/notes.md': 'eval(code)'})
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'feature')
    summary = tmp_path / 'summary.md'
    assert scan_repo.main([str(tmp_path), '--base', 'main', '--json', '--markdown', str(summary)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == ['app/build/handler.py', 'coverage/report.js', 'dist/bundle.js', 'web/vendor/lib.js']
    assert {f['path'] for f in report['findings'] if f['priority'] == 'P1' and f['new']} == set(report['files'])
    # Still left out, but listed rather than skipped silently.
    assert report['skipped_changed_files'] == ['node_modules/pkg/index.js', 'public/app.min.js']
    assert summary.read_text().endswith('Skipped changed files (dependency or tool folders, or minified): '
                                        '`node_modules/pkg/index.js`, `public/app.min.js`.\n')
    assert scan_repo.main([str(tmp_path), '--base', 'main']) == 1
    out = capsys.readouterr().out
    assert 'Skipped: .git, .hg, .svn, .venv, venv, __pycache__, node_modules folders and minified' in out
    assert 'Skipped changed files: node_modules/pkg/index.js, public/app.min.js\n' in out


def test_full_scan_exits_with_two_when_a_folder_cannot_be_listed(tmp_path, monkeypatch, capsys):
    root = project(tmp_path, {'app.js': 'const a = 1;', 'src/secret/x.js': 'eval(code);'})
    locked, scandir = root / 'src' / 'secret', scan_repo.os.scandir
    def refuse(path='.'):
        if Path(path) == locked:
            raise PermissionError(13, 'Permission denied', str(path))
        return scandir(path)
    monkeypatch.setattr(scan_repo.os, 'scandir', refuse)
    assert scan_repo.main([str(root)]) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'no result issued' in captured.err and 'secret' in captured.err


@pytest.mark.skipif(not hasattr(scan_repo.os, 'geteuid') or scan_repo.os.geteuid() == 0,
                    reason='needs a user that file permissions apply to')
def test_full_scan_exits_with_two_on_a_folder_without_read_permission(tmp_path, capsys):
    root = project(tmp_path, {'app.js': 'const a = 1;', 'src/secret/x.js': 'eval(code);'})
    (root / 'src' / 'secret').chmod(0)
    try:
        assert scan_repo.main([str(root)]) == 2
    finally:
        (root / 'src' / 'secret').chmod(0o755)
    assert 'no result issued' in capsys.readouterr().err


# --sarif: write the triaged findings as SARIF 2.1.0 (F-1.1). Fixtures use ASCII paths only.

def test_sarif_mirrors_the_json_findings_for_a_full_scan(tmp_path, capsys):
    root = project(tmp_path)
    out = tmp_path / 'out.sarif'
    assert scan_repo.main([str(root), '--sarif', str(out), '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    doc = json.loads(out.read_text())
    assert doc['version'] == '2.1.0' and len(doc['runs']) == 1
    run = doc['runs'][0]
    assert run['tool']['driver']['name'] == 'sast-triage'
    # each reported rule id once, in first-appearance order
    assert [r['id'] for r in run['tool']['driver']['rules']] == \
        list(dict.fromkeys(f['rule_id'] for f in report['findings']))
    # one result per --json finding, in the same order, with the same fields
    assert len(run['results']) == len(report['findings'])
    for result, f in zip(run['results'], report['findings']):
        location = result['locations'][0]['physicalLocation']
        assert result['ruleId'] == f['rule_id']
        assert location['artifactLocation']['uri'] == f['path'] and '\\' not in f['path']
        assert location['region']['startLine'] == f['start_line']
        assert location['region']['endLine'] == f['end_line']
        assert result['partialFingerprints']['fingerprint'] == f['fingerprint']
        assert result['properties'] == {'priority': f['priority'], 'new': f['new'],
                                        'new_because': f['new_because'], 'cwe': f['cwe']}
    # level follows the Check Run annotations: new P1 -> error, new P2 -> warning
    assert [r['level'] for r in run['results']] == ['error', 'error', 'warning', 'warning']


def test_sarif_labels_new_and_pre_existing_findings_with_base(tmp_path, capsys):
    root = repository(tmp_path)
    out = tmp_path / 'out.sarif'
    assert scan_repo.main([str(root), '--base', 'main', '--sarif', str(out), '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    results = json.loads(out.read_text())['runs'][0]['results']
    by_json = {(f['path'], f['start_line'], f['rule_id']): f for f in report['findings']}
    assert len(results) == len(report['findings'])
    for result in results:
        location = result['locations'][0]['physicalLocation']
        f = by_json[(location['artifactLocation']['uri'], location['region']['startLine'], result['ruleId'])]
        assert result['properties']['new'] == f['new']
        assert result['properties']['new_because'] == f['new_because']
    # the one pre-existing P1 is a note, not an error
    preexisting = [r for r in results if r['properties']['new'] is False]
    assert len(preexisting) == 1 and preexisting[0]['level'] == 'note'
    assert preexisting[0]['properties']['priority'] == 'P1'


def test_sarif_is_one_empty_run_when_there_is_nothing_to_scan(tmp_path):
    root = project(tmp_path, {'README.md': 'nothing to scan'})
    out = tmp_path / 'out.sarif'
    assert scan_repo.main([str(root), '--sarif', str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc['version'] == '2.1.0' and len(doc['runs']) == 1
    assert doc['runs'][0]['tool']['driver']['name'] == 'sast-triage'
    assert doc['runs'][0]['results'] == []


def test_sarif_is_not_written_on_a_scanner_or_size_error(tmp_path, monkeypatch, capsys):
    root = project(tmp_path / 'repo', {'app.js': 'eval(code);'})
    out = tmp_path / 'out.sarif'
    out.write_bytes(b'OLD')                                   # an existing file must stay unchanged
    def broken(*a, **k):
        raise runner.SemgrepInvocationError(65, ['semgrep'], '', 'boom')
    with monkeypatch.context() as m:
        m.setattr(scan_repo, 'run_semgrep', broken)
        assert scan_repo.main([str(root), '--sarif', str(out)]) == 2
    assert 'scan incomplete' in capsys.readouterr().err
    assert out.read_bytes() == b'OLD'                         # neither created nor overwritten
    fresh = tmp_path / 'fresh.sarif'
    (root / 'big.js').write_text('x' * (1024 * 1024 + 1))     # over the 1 MiB per-file limit
    assert scan_repo.main([str(root), '--sarif', str(fresh)]) == 2
    assert 'big.js' in capsys.readouterr().err and not fresh.exists()


def test_sarif_does_not_change_the_other_output(tmp_path, capsys):
    root = project(tmp_path)
    assert scan_repo.main([str(root), '--json']) == 1
    json_without = capsys.readouterr().out
    assert scan_repo.main([str(root), '--json', '--sarif', str(tmp_path / 'a.sarif')]) == 1
    assert capsys.readouterr().out == json_without
    assert scan_repo.main([str(root)]) == 1
    console_without = capsys.readouterr().out
    assert scan_repo.main([str(root), '--sarif', str(tmp_path / 'b.sarif')]) == 1
    assert capsys.readouterr().out == console_without
    md_without, md_with = tmp_path / 'without.md', tmp_path / 'with.md'
    scan_repo.main([str(root), '--markdown', str(md_without)]); capsys.readouterr()
    scan_repo.main([str(root), '--markdown', str(md_with), '--sarif', str(tmp_path / 'c.sarif')]); capsys.readouterr()
    assert md_without.read_text() == md_with.read_text()


def test_sarif_unwritable_destination_exits_two_without_a_partial_artifact(tmp_path, capsys):
    root = project(tmp_path, {'app.js': 'const a = 1;'})      # a clean scan that would otherwise exit 0
    target = tmp_path / 'no_such_dir' / 'out.sarif'           # the parent directory does not exist
    assert scan_repo.main([str(root), '--sarif', str(target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'could not write the SARIF file' in captured.err
    assert not target.exists() and not target.parent.exists()


def test_sarif_is_written_when_only_the_base_version_scan_fails(tmp_path, monkeypatch, capsys):
    # When only the base-version scan fails, the CLI warns, counts every finding as new and still
    # issues a result (exit 1). AC7 forbids --sarif from changing the exit status, so FILE must be
    # written and mirror --json, whether the destination is fresh or already exists.
    root = repository(tmp_path)
    real, calls = scan_repo.run_semgrep, []
    def head_only(paths, repo_root, **options):
        calls.append(repo_root)
        if len(calls) > 1:                                  # the second scan is the base versions
            raise runner.SemgrepInvocationError(2, ['semgrep'], '', 'the old version does not parse')
        return real(paths, repo_root, **options)
    monkeypatch.setattr(scan_repo, 'run_semgrep', head_only)

    # same exit status with and without --sarif, and --json output is unchanged
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    without = json.loads(capsys.readouterr().out)
    calls.clear()
    fresh = tmp_path / 'fresh.sarif'
    assert scan_repo.main([str(root), '--base', 'main', '--json', '--sarif', str(fresh)]) == 1
    with_sarif = json.loads(capsys.readouterr().out)
    assert with_sarif == without
    assert with_sarif['findings'] and all(f['new'] for f in with_sarif['findings'])   # the fallback: every finding new

    results = json.loads(fresh.read_text())['runs'][0]['results']
    assert [r['ruleId'] for r in results] == [f['rule_id'] for f in with_sarif['findings']]
    assert all(r['properties']['new'] is True for r in results)

    # a pre-existing destination is overwritten with the issued result, not left stale
    existing = tmp_path / 'old.sarif'
    existing.write_bytes(b'OLD')
    calls.clear()
    assert scan_repo.main([str(root), '--base', 'main', '--sarif', str(existing)]) == 1
    capsys.readouterr()
    overwritten = json.loads(existing.read_text())['runs'][0]['results']
    assert [r['ruleId'] for r in overwritten] == [f['rule_id'] for f in with_sarif['findings']]


# --base without the history it needs (F-1.2): exit 2, no result, and the error says what to fetch.
# Fixtures use ASCII file and ref names only.

def command_line(*arguments):
    """Run scan_repo.py the way a user does, for its real exit status, stdout and stderr."""
    return subprocess.run([sys.executable, 'scan_repo.py', *map(str, arguments)], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)


def shallow_clone(tmp_path, *options):
    """`git clone --depth 1` of repository(), on its feature branch: one commit deep, no history."""
    origin = repository(tmp_path / 'origin')
    clone = tmp_path / 'clone'
    git(tmp_path, 'clone', '-q', '--depth', '1', '--branch', 'feature', *options, origin.as_uri(), str(clone))
    assert (clone / '.git' / 'shallow').is_file()
    return clone


def test_base_ref_missing_from_the_checkout_exits_two_names_it_and_says_how_to_fetch_it(tmp_path):
    root = repository(tmp_path / 'repo')
    sarif, summary = tmp_path / 'out.sarif', tmp_path / 'summary.md'
    for output in ([], ['--json'], ['--sarif', sarif, '--markdown', summary]):
        result = command_line(root, '--base', 'origin/missing', *output)
        assert result.returncode == 2, result.stderr
        assert result.stdout == '' and not sarif.exists() and not summary.exists()      # no result
        assert 'error: cannot diff against origin/missing, no result issued.' in result.stderr
        assert 'origin/missing is not a commit in this checkout' in result.stderr
        assert '`git fetch' in result.stderr and '`fetch-depth: 0`' in result.stderr


@pytest.mark.parametrize('base', ['origin/main', 'HEAD~1'])
def test_base_ref_left_out_of_a_shallow_clone_exits_two_and_says_how_to_fetch_it(tmp_path, capsys, base):
    clone = shallow_clone(tmp_path)               # a single-branch clone: neither the base branch nor HEAD's parent
    assert scan_repo.main([str(clone), '--base', base, '--json']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and f'cannot diff against {base}, no result issued' in captured.err
    assert f'{base} is not a commit in this checkout' in captured.err
    assert '`git fetch' in captured.err and '`fetch-depth: 0`' in captured.err


def test_shallow_clone_without_the_merge_base_exits_two_and_says_no_merge_base_was_found(tmp_path, capsys):
    clone = shallow_clone(tmp_path, '--no-single-branch')
    git(clone, 'rev-parse', '--verify', '--quiet', 'origin/main^{commit}')        # the base ref exists here
    sarif, summary = tmp_path / 'out.sarif', tmp_path / 'summary.md'
    for output in ([], ['--json'], ['--sarif', sarif, '--markdown', summary]):
        result = command_line(clone, '--base', 'origin/main', *output)
        assert result.returncode == 2, result.stderr
        assert result.stdout == '' and not sarif.exists() and not summary.exists()      # no result
        assert 'error: cannot diff against origin/main, no result issued.' in result.stderr
        assert 'no merge base was found' in result.stderr and '`fetch-depth: 0`' in result.stderr
        assert 'is not a commit in this checkout' not in result.stderr
    # Once the history is there, the same command on the same clone issues a result.
    git(clone, 'fetch', '-q', '--unshallow')
    assert scan_repo.main([str(clone), '--base', 'origin/main', '--json']) == 1
    captured = capsys.readouterr()
    assert captured.err == '' and json.loads(captured.out)['files'] == ['src/cache.py', 'src/legacy.py', 'web/app.js']


def test_unrelated_history_in_a_full_clone_also_exits_two_with_no_merge_base_found(tmp_path, capsys):
    root = repository(tmp_path)
    git(root, 'switch', '-q', '--orphan', 'unrelated')
    project(root, {'solo.py': 'x = 1'})
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'a second root commit')
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'cannot diff against main, no result issued' in captured.err
    assert 'no merge base was found for main and HEAD' in captured.err


@pytest.mark.parametrize('base', ['--output=x', '-x'])
def test_base_starting_with_a_dash_is_refused_with_exit_two_before_git_runs(tmp_path, monkeypatch, capsys, base):
    root = repository(tmp_path)

    def no_git(*a, **k):
        raise AssertionError('git must not run for a base that starts with a dash')
    monkeypatch.setattr(scan_repo.subprocess, 'run', no_git)
    assert scan_repo.main([str(root), f'--base={base}']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'no result issued' in captured.err and f'invalid base: {base}' in captured.err
    assert 'fetch' not in captured.err              # refused as invalid, not reported as missing history
    with pytest.raises(SystemExit) as error:        # as a separate argument, the option parser refuses it
        scan_repo.main([str(root), '--base', base])
    assert error.value.code == 2 and capsys.readouterr().out == ''


def test_other_git_failures_keep_their_own_message_and_get_no_fetch_hint(tmp_path, monkeypatch, capsys):
    # Outside a git repository git says so itself: the base is not "missing from this checkout".
    assert scan_repo.main([str(project(tmp_path / 'plain', {'a.py': 'x = 1'})), '--base', 'main']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'cannot diff against main, no result issued' in captured.err
    assert 'is not a commit in this checkout' not in captured.err and 'fetch-depth' not in captured.err
    # A merge-base lookup that fails for another reason still stops the scan, with git's own words.
    root, real = repository(tmp_path / 'repo'), scan_repo.subprocess.run

    def broken_merge_base(command, *a, **k):
        if 'merge-base' in command:
            return subprocess.CompletedProcess(command, 128, stdout='', stderr='fatal: bad object\n')
        return real(command, *a, **k)
    monkeypatch.setattr(scan_repo.subprocess, 'run', broken_merge_base)
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'cannot diff against main, no result issued.\nfatal: bad object' in captured.err
    assert 'no merge base was found' not in captured.err and 'fetch-depth' not in captured.err


# A successful --base scan, pinned to what 2.2.0 printed: checking for the history must not change it.
BASE_REPORT = '''\
sast-triage scan of {directory}, changes since main
A finding is new when it covers a line changed since the base, or was not in the file before; only a new P1 fails.
1 changed Python, JavaScript and TypeScript files, 41 service-owned rules.
Skipped: .git, .hg, .svn, .venv, venv, __pycache__, node_modules folders and minified *.min.js files.

Changes since main (1 files): FAILURE
  [P1, new] server.js:4  js-child-process-exec  (line unchanged; not in the base version)
### sast-triage — Semgrep summary

**Gate: FAIL** — 1 new P1 finding:
- `server.js:4` js-child-process-exec

| Priority | New | Pre-existing |
|---|---|---|
| P1 | 1 | 0 |
| P2 | 0 | 0 |
| P3 | 0 | 0 |

P1: high or critical severity in runtime code. P2: high or critical in test code, or medium in runtime code. \
P3: everything else. New: on lines changed since main, or not in the file before those changes.
'''
BASE_FINDING = {
    'path': 'server.js', 'start_line': 4, 'end_line': 4, 'severity': 'HIGH', 'rule_id': 'js-child-process-exec',
    'title': 'child_process exec/execSync runs a shell command built at runtime (possible command injection)',
    'message': 'child_process exec/execSync runs a shell command built at runtime (possible command injection)',
    'fix': None, 'cwe': 'CWE-78', 'owasp': 'A03:2021', 'confidence': None, 'likelihood': None,
    'fingerprint': '41093c0958e7832b', 'new': True, 'new_because': 'not in the base version', 'test_code': False,
    'priority': 'P1',
}


def base_json(directory, file, conclusion, findings):
    """The exact --json text of a one-file --base scan against main."""
    counts = {priority: {'new': sum(f['priority'] == priority for f in findings), 'pre-existing': 0}
              for priority in ('P1', 'P2', 'P3')}
    return json.dumps({'directory': str(directory), 'scan': 'changes since main', 'base': 'main', 'files_scanned': 1,
                       'files': [file], 'rules': 41, 'skipped_changed_files': [], 'conclusion': conclusion,
                       'counts': counts, 'findings': findings}, indent=2) + '\n'


def test_successful_base_scan_exit_status_and_output_are_unchanged(tmp_path, capsys):
    root = introduced_elsewhere(tmp_path)
    assert scan_repo.main([str(root), '--base', 'main']) == 1                 # the gate fails: exit 1
    captured = capsys.readouterr()
    assert captured.out == BASE_REPORT.format(directory=root) and captured.err == ''
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    captured = capsys.readouterr()
    assert captured.out == base_json(root, 'server.js', 'failure', [BASE_FINDING]) and captured.err == ''
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'tidy')
    project(root, {'other.js': 'const n = 2;'})
    git(root, 'commit', '-q', '-am', 'tidy')
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 0       # the gate passes: exit 0
    captured = capsys.readouterr()
    assert captured.out == base_json(root, 'other.js', 'success', []) and captured.err == ''


# The Action's `timeout` input (F-1.3). The Scan step of action.yml runs here the way the runner runs it:
# the inputs fill in the step's `env`, then bash runs its script. A stub interpreter records the arguments
# scan_repo.py is given; when not stubbed it then runs them for the real exit status and summary.
# ASCII names only.

def action_definition():
    return yaml.safe_load((ROOT / 'action.yml').read_text())


def action_scan_step():
    return next(step for step in action_definition()['runs']['steps'] if step['name'] == 'Scan')


@pytest.fixture
def scan_step(tmp_path):
    """Run the Scan step for the given Action inputs; inputs left out keep their action.yml defaults.

    Each run gets its own RUNNER_TEMP, and its interpreter records the arguments it is given. With
    stub=True it does nothing else; otherwise it passes them on to the installed test environment, so the
    suite does not pip install or use the network. base_ref is GITHUB_BASE_REF, set on pull request events.
    cwd is the step's working directory: on a runner, the job's workspace."""
    runs = []

    def run(directory, stub=False, base_ref=None, cwd=ROOT, **inputs):
        values = {name: str(declared.get('default', '')) for name, declared in action_definition()['inputs'].items()}
        values.update(inputs, path=str(directory))
        step = action_scan_step()
        runner_temp = tmp_path / f'runner temp {len(runs)}'
        runs.append(runner_temp)
        interpreter = runner_temp / 'sast-triage-venv' / 'bin' / 'python'
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$RUNNER_TEMP/arguments"\n'
                               + ('' if stub else f'exec {shlex.quote(sys.executable)} "$@"\n'))
        interpreter.chmod(0o755)
        env = {key: os.environ[key] for key in ('HOME', 'PATH', 'LANG', 'TZ') if key in os.environ}
        env.update({'RUNNER_TEMP': str(runner_temp), 'GITHUB_ACTION_PATH': str(ROOT),
                    'GITHUB_STEP_SUMMARY': str(runner_temp / 'summary.md'), 'PRSEC_LOAD_DOTENV': '0',
                    'PRSEC_MODE': 'local', 'PRSEC_SCANNER_BACKEND': 'local'})
        if base_ref:
            env['GITHUB_BASE_REF'] = base_ref
        env.update({name: re.sub(r'\$\{\{ *inputs\.(\w+) *\}\}', lambda match: values[match[1]], value)
                    for name, value in step.get('env', {}).items()})
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step['run']],
                                cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
        result.runner_temp = runner_temp
        result.report = runner_temp / 'sast-triage.md'
        result.summary = (runner_temp / 'summary.md').read_bytes() if (runner_temp / 'summary.md').exists() else None
        result.arguments = (runner_temp / 'arguments').read_text().splitlines()
        return result

    return run


def pre_existing_only(tmp_path):
    """repository() on a branch whose one change leaves its P1 on an untouched line: main passes, a full scan fails."""
    root = repository(tmp_path)
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'docs-only')
    project(root, {'src/legacy.py': "import os\nos.popen('ls')\n# reviewed"})
    git(root, 'commit', '-q', '-am', 'comment')
    return root


def test_action_declares_an_optional_timeout_input_with_an_empty_default():
    declared = action_definition()['inputs']['timeout']
    assert declared['default'] == '' and not declared.get('required') and declared['description']


@pytest.mark.parametrize('inputs,base_ref,base_arguments', [
    ({'base': 'none'}, 'main', []),                              # base: none, a full scan even on a pull request
    ({}, None, []),                                              # no base and no pull request: a full scan
    ({'base': 'release'}, 'main', ['--base', 'release']),        # a base ref
    ({}, 'main', ['--base', 'origin/main']),                     # a pull request's base branch
], ids=['base-none', 'no-base', 'base-ref', 'pull-request-base'])
def test_action_timeout_empty_keeps_todays_arguments_and_600_adds_timeout_600(tmp_path, scan_step, inputs, base_ref,
                                                                             base_arguments):
    for timeout, added in (({}, []), ({'timeout': ''}, []), ({'timeout': '600'}, ['--timeout', '600'])):
        result = scan_step(tmp_path, stub=True, base_ref=base_ref, **inputs, **timeout)
        assert result.returncode == 0, result.stderr
        assert result.arguments == [str(ROOT / 'scan_repo.py'), str(tmp_path), '--markdown', str(result.report),
                                    *base_arguments, *added], timeout


def test_action_timeout_reaches_the_script_only_through_an_environment_variable(tmp_path, scan_step):
    definition = action_definition()
    assert [value for value in action_scan_step()['env'].values() if 'timeout' in value] == ['${{ inputs.timeout }}']
    assert (ROOT / 'action.yml').read_text().count('inputs.timeout') == 1
    for step in definition['runs']['steps']:
        assert '${{' not in step.get('run', ''), f"{step['name']}: an expression is expanded inside the run script"
    # The value stays one argument: bash does not split it, and never runs it.
    hostile = '600 --json; touch "$RUNNER_TEMP/ran" $(touch "$RUNNER_TEMP/ran") `touch "$RUNNER_TEMP/ran"`'
    result = scan_step(tmp_path, stub=True, timeout=hostile)
    assert result.returncode == 0, result.stderr
    assert result.arguments[-2:] == ['--timeout', hostile] and not (result.runner_temp / 'ran').exists()


def test_readme_github_action_documents_the_timeout_input_and_its_default():
    section = (ROOT / 'README.md').read_text().split('\n## GitHub Action\n')[1].split('\n## ')[0]
    rows = [line for line in section.splitlines() if line.startswith('| `timeout` |')]
    assert len(rows) == 1, 'the inputs table of README "GitHub Action" needs one `timeout` row'
    default = json.dumps(action_definition()['inputs']['timeout']['default'])        # "", as the README writes it
    assert rows[0].startswith(f'| `timeout` | `{default}` |') and '`--timeout`' in rows[0] and '300 seconds' in rows[0]
    assert f'    timeout: {default} ' in section, 'the workflow example shows the default too'


@pytest.mark.parametrize('base', ['main', 'none'], ids=['base-ref', 'base-none'])
def test_action_timeout_that_is_not_a_whole_number_exits_two_with_no_result_as_the_command_line_does(tmp_path,
                                                                                                    scan_step, base):
    root = pre_existing_only(tmp_path / 'checkout')
    for timeout in ('abc', '1.5', '10s', ' ', '600 --json', '--help'):
        cli = command_line(root, '--timeout', timeout)
        result = scan_step(root, base=base, timeout=timeout)
        assert (cli.returncode, result.returncode) == (2, 2), (timeout, result.stderr)
        assert 'scan_repo.py: error: argument --timeout: ' in result.stderr, timeout
        assert result.stderr.splitlines()[-1] == cli.stderr.splitlines()[-1], timeout
        assert result.stdout == '' and result.summary is None and not result.report.exists(), timeout


@pytest.mark.parametrize('base,code,gate', [
    ('main', 0, b'**Gate: PASS**'),          # a base ref: the P1 is on an untouched line, so pre-existing
    ('none', 1, b'**Gate: FAIL**'),          # base: none: a full scan, where every finding is new
], ids=['base-ref', 'base-none'])
def test_action_timeout_leaves_the_base_arguments_and_gate_result_unchanged(tmp_path, scan_step, base, code, gate):
    root = pre_existing_only(tmp_path / 'checkout')
    base_arguments = [] if base == 'none' else ['--base', base]
    empty = scan_step(root, base=base)
    assert empty.returncode == code, empty.stderr
    assert empty.arguments[4:] == base_arguments and gate in empty.summary
    valid = scan_step(root, base=base, timeout='600')
    assert valid.returncode == code, valid.stderr
    assert valid.arguments[4:] == [*base_arguments, '--timeout', '600']
    assert (valid.stdout, valid.summary) == (empty.stdout, empty.summary)


# The Action's `sarif` input (F-1.5): the Scan step passes it to scan_repo.py as --sarif. The step runs here as
# for `timeout` above. File names are ASCII only; the SARIF paths have spaces in them.

SARIF_EXAMPLE = 'sast-triage.sarif'           # the path the README workflow example writes and uploads
# The `if` of the README's upload step: a completed scan, whether or not the gate failed.
UPLOAD_IF = "${{ !cancelled() && steps.scan.outcome != 'skipped' && hashFiles('sast-triage.sarif') != '' }}"
ACTION_BASES = pytest.mark.parametrize('inputs,base_ref,base_arguments', [
    ({'base': 'none'}, 'main', []),                              # base: none, a full scan even on a pull request
    ({}, None, []),                                              # no base and no pull request: a full scan
    ({'base': 'release'}, 'main', ['--base', 'release']),        # a base ref
    ({}, 'main', ['--base', 'origin/main']),                     # a pull request's base branch
], ids=['base-none', 'no-base', 'base-ref', 'pull-request-base'])
FULL_AND_BASE = pytest.mark.parametrize('base,code,labels', [
    # a base ref: the P1 is on an untouched line, so pre-existing, and the gate passes
    ('main', 0, [('py-os-popen', False, 'note')]),
    # base: none: a full scan, where every finding is new, and the P1 fails the gate
    ('none', 1, [('py-os-popen', True, 'error'), ('py-weak-md5', True, 'warning'),
                 ('py-insecure-deserialization-pickle-loads', True, 'warning')]),
], ids=['base-ref', 'base-none'])


def readme_github_action():
    return (ROOT / 'README.md').read_text().split('\n## GitHub Action\n')[1].split('\n## ')[0]


def readme_upload_job():
    """The one job of the README "GitHub Action" workflow example that uploads the SARIF file."""
    examples = [text for text in re.findall(r'```yaml\n(.*?)```', readme_github_action(), re.S) if 'upload-sarif' in text]
    assert len(examples) == 1, 'README "GitHub Action" needs one workflow example with an upload step'
    (job,) = yaml.safe_load(examples[0])['jobs'].values()
    return job


def tree(folder):
    """Every path under `folder` with its type and, for a file, its bytes: to show a run left nothing behind."""
    return sorted((path.relative_to(folder).as_posix(), path.is_dir(), None if path.is_dir() else path.read_bytes())
                  for path in folder.rglob('*'))


def test_action_declares_an_optional_sarif_input_with_an_empty_default():
    declared = action_definition()['inputs']['sarif']
    assert declared['default'] == '' and not declared.get('required') and declared['description']


@ACTION_BASES
def test_action_sarif_empty_leaves_the_arguments_unchanged_and_a_path_adds_sarif_with_that_path(
        tmp_path, scan_step, inputs, base_ref, base_arguments):
    absolute, relative = str(tmp_path / 'scan results' / 'sast triage.sarif'), 'scan results/sast triage.sarif'
    for sarif, added in (({}, []), ({'sarif': ''}, []),
                         ({'sarif': absolute}, ['--sarif', absolute]),
                         ({'sarif': relative}, ['--sarif', relative]),
                         ({'sarif': absolute, 'timeout': '600'}, ['--timeout', '600', '--sarif', absolute])):
        result = scan_step(tmp_path, stub=True, base_ref=base_ref, **inputs, **sarif)
        assert result.returncode == 0, result.stderr
        assert result.arguments == [str(ROOT / 'scan_repo.py'), str(tmp_path), '--markdown', str(result.report),
                                    *base_arguments, *added], sarif


def test_action_sarif_reaches_the_script_only_through_an_environment_variable(tmp_path, scan_step):
    assert [value for value in action_scan_step()['env'].values() if 'sarif' in value] == ['${{ inputs.sarif }}']
    assert (ROOT / 'action.yml').read_text().count('inputs.sarif') == 1
    for step in action_definition()['runs']['steps']:
        assert '${{' not in step.get('run', ''), f"{step['name']}: an expression is expanded inside the run script"
    # The value stays one argument: bash does not split it, and never runs it.
    hostile = 'out.sarif --json; touch "$RUNNER_TEMP/ran" $(touch "$RUNNER_TEMP/ran") `touch "$RUNNER_TEMP/ran"`'
    result = scan_step(tmp_path, stub=True, sarif=hostile)
    assert result.returncode == 0, result.stderr
    assert result.arguments[-2:] == ['--sarif', hostile] and not (result.runner_temp / 'ran').exists()


@FULL_AND_BASE
def test_action_sarif_writes_the_file_for_a_full_and_a_base_scan_at_a_path_with_spaces(tmp_path, scan_step, base, code,
                                                                                      labels):
    root = pre_existing_only(tmp_path / 'check out')
    base_arguments = [] if base == 'none' else ['--base', base]
    without = scan_step(root, base=base)
    assert without.returncode == code, without.stderr
    by_command_line = tmp_path / 'command line.sarif'
    assert command_line(root, *base_arguments, '--sarif', by_command_line).returncode == code
    (tmp_path / 'scan results').mkdir()
    (root / 'scan results').mkdir()
    for sarif, written in (
            (str(tmp_path / 'scan results' / 'sast triage.sarif'), tmp_path / 'scan results' / 'sast triage.sarif'),
            # A relative path is relative to the step's working directory, the workspace: here the checkout.
            ('scan results/sast triage.sarif', root / 'scan results' / 'sast triage.sarif')):
        result = scan_step(root, base=base, sarif=sarif, cwd=root)
        assert result.returncode == code, result.stderr
        assert result.arguments[4:] == [*base_arguments, '--sarif', sarif]
        # The same file the command line writes for this scan, and no other file beside it.
        assert written.read_bytes() == by_command_line.read_bytes()
        assert [path.name for path in written.parent.iterdir()] == ['sast triage.sarif']
        # The gate result, the report and the job summary are the ones of a scan without the input.
        assert (result.stdout, result.summary) == (without.stdout, without.summary)
    document = json.loads(by_command_line.read_text())
    assert document['version'] == '2.1.0' and len(document['runs']) == 1
    assert [(r['ruleId'], r['properties']['new'], r['level']) for r in document['runs'][0]['results']] == labels


@pytest.mark.parametrize('inputs', [
    {'base': 'none'},                              # a full scan with a file over the 1 MiB limit
    {'base': 'main'},                              # the same file, changed since the base
    {'base': 'origin/missing'},                    # a base ref that is not in the checkout
    {'base': 'none', 'timeout': 'abc'},            # a usage error
], ids=['full-scan-size-limit', 'base-scan-size-limit', 'base-ref-missing', 'usage-error'])
def test_action_sarif_is_not_created_and_an_existing_file_is_unchanged_when_the_scan_exits_two(tmp_path, scan_step,
                                                                                              inputs):
    root = pre_existing_only(tmp_path / 'check out')
    project(root, {'big.js': 'x' * (1024 * 1024 + 1)})
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'a file over the limit')
    folder = tmp_path / 'scan results'
    folder.mkdir()
    (folder / 'existing file.sarif').write_bytes(b'OLD')
    before = tree(folder)
    for name in ('fresh file.sarif', 'existing file.sarif'):
        result = scan_step(root, sarif=str(folder / name), **inputs)
        assert result.returncode == 2, result.stderr
        assert result.arguments[-2:] == ['--sarif', str(folder / name)]
        assert result.stdout == '' and result.summary is None and not result.report.exists()      # no result
        assert tree(folder) == before, name                  # nothing created, the existing file unchanged


@pytest.mark.parametrize('base', ['main', 'none'], ids=['base-ref', 'base-none'])
def test_action_sarif_path_that_cannot_be_written_exits_two_with_no_partial_artifact(tmp_path, scan_step, base):
    root = pre_existing_only(tmp_path / 'check out')
    folder = tmp_path / 'scan results'
    (folder / 'a folder.sarif').mkdir(parents=True)             # the path is a folder
    (folder / 'a file').write_bytes(b'KEPT')                    # the path is below a file
    (folder / 'read only').mkdir()
    (folder / 'read only' / 'existing file.sarif').write_bytes(b'OLD')
    targets = [folder / 'no such folder' / 'out.sarif', folder / 'a folder.sarif', folder / 'a file' / 'out.sarif']
    if hasattr(os, 'geteuid') and os.geteuid() != 0:            # file permissions do not stop root
        targets += [folder / 'read only' / 'fresh file.sarif', folder / 'read only' / 'existing file.sarif']
    before = tree(folder)
    (folder / 'read only').chmod(0o555)
    try:
        for target in targets:
            result = scan_step(root, base=base, sarif=str(target))
            assert result.returncode == 2, (target, result.stderr)
            assert 'could not write the SARIF file' in result.stderr and 'no result issued' in result.stderr
            assert result.stdout == '', target                   # no report either
            assert tree(folder) == before, target                # no SARIF file, whole or partial, and no temporary
    finally:
        (folder / 'read only').chmod(0o755)


@pytest.mark.parametrize('base', ['main', 'none'], ids=['base-ref', 'base-none'])
def test_action_sarif_path_that_is_not_a_valid_argument_exits_two_before_the_scan(tmp_path, scan_step, base):
    root = pre_existing_only(tmp_path / 'check out')
    workspace = tmp_path / 'work space'
    workspace.mkdir()
    for sarif in ('--json', '-o', '--sarif'):                    # a path can't start with a dash: write ./-o
        cli = command_line(root, '--sarif', sarif)
        result = scan_step(root, base=base, sarif=sarif, cwd=workspace)
        assert (cli.returncode, result.returncode) == (2, 2), (sarif, result.stderr)
        assert 'scan_repo.py: error: argument --sarif: expected one argument' in result.stderr, sarif
        assert result.stderr.splitlines()[-1] == cli.stderr.splitlines()[-1], sarif
        assert result.stdout == '' and result.summary is None and not result.report.exists(), sarif
        assert tree(workspace) == [], sarif


def test_readme_github_action_documents_the_sarif_input_and_its_default():
    section = readme_github_action()
    rows = [line for line in section.splitlines() if line.startswith('| `sarif` |')]
    assert len(rows) == 1, 'the inputs table of README "GitHub Action" needs one `sarif` row'
    default = json.dumps(action_definition()['inputs']['sarif']['default'])          # "", as the README writes it
    assert rows[0].startswith(f'| `sarif` | `{default}` |') and '`--sarif`' in rows[0]
    assert f'    sarif: {default} ' in section, 'the workflow example shows the default too'
    assert len(action_definition()['inputs']) == 4 and 'All four inputs are optional' in section


def test_readme_github_action_shows_a_separate_upload_step_pinned_to_a_full_commit_sha():
    section, job = readme_github_action(), readme_upload_job()
    steps = job['steps']
    (scan,) = [step for step in steps if step.get('uses', '').startswith('lansiquo/sast-triage@')]
    (upload,) = [step for step in steps if step.get('uses', '').startswith('github/codeql-action/upload-sarif@')]
    assert steps.index(upload) > steps.index(scan)                # a step of the user's workflow, after the scan
    assert re.fullmatch(r'[0-9a-f]{40}', upload['uses'].split('@')[1]), 'pin the upload step to a full commit SHA'
    assert scan['with'] == {'sarif': SARIF_EXAMPLE} and upload['with'] == {'sarif_file': SARIF_EXAMPLE}
    # It needs security-events: write, and the README says so.
    assert job['permissions']['security-events'] == 'write' and '`security-events: write`' in section
    # sast-triage itself still uses no token and no other actions: said in the README, and true of action.yml.
    assert 'uses no token and no other actions' in ' '.join(section.split())
    assert all('uses' not in step for step in action_definition()['runs']['steps'])
    assert 'token' not in (ROOT / 'action.yml').read_text().lower()


def test_readme_upload_step_checks_for_a_completed_scan_so_it_never_uploads_a_stale_file(tmp_path, scan_step):
    steps = readme_upload_job()['steps']
    clean, scan, upload = steps[-3:]
    assert clean == {'run': f'rm -rf {SARIF_EXAMPLE}'}            # the step right before the scan
    assert scan['id'] == 'scan' and upload['if'] == UPLOAD_IF
    assert [step for step in steps if 'run' in step] == [clean]  # and no step prints the file to the log

    root = pre_existing_only(tmp_path / 'check out')              # the job's workspace
    path, outside = root / SARIF_EXAMPLE, tmp_path / 'outside.sarif'
    outside.write_bytes(b'OLD')

    def upload_runs(outcome):
        """UPLOAD_IF in a job that was not cancelled, given the Scan step's outcome.

        hashFiles() is empty unless its pattern matches a file in the workspace; a folder matches through
        the files in it."""
        matched = path.is_file() or (path.is_dir() and any(found.is_file() for found in path.rglob('*')))
        return outcome != 'skipped' and matched

    def job(stale, **inputs):
        """The example's steps after the checkout, which brought `stale` along at the SARIF path."""
        stale()
        assert upload_runs('skipped') is False                    # an earlier step failed: the scan never ran
        subprocess.run(['bash', '--noprofile', '--norc', '-e', '-c', clean['run']], cwd=root, check=True, timeout=60)
        return scan_step(root, sarif=SARIF_EXAMPLE, cwd=root, **inputs)

    def stale_folder():
        path.mkdir()
        (path / 'old.sarif').write_bytes(b'OLD')

    stale_file, stale_link = (lambda: path.write_bytes(b'OLD')), (lambda: path.symlink_to(outside))
    # A completed scan, exit 0 or exit 1: the file is this scan's own, and the step uploads it.
    for stale, base, code, outcome in ((stale_file, 'main', 0, 'success'), (stale_folder, 'none', 1, 'failure')):
        result = job(stale, base=base)
        assert result.returncode == code, result.stderr
        assert path.is_file() and not path.is_symlink() and json.loads(path.read_text())['version'] == '2.1.0'
        assert upload_runs(outcome) is True
        path.unlink()
    # A scan that stops with exit status 2: nothing is at the path, so nothing is uploaded.
    (root / 'big.js').write_text('x' * (1024 * 1024 + 1))        # over the 1 MiB per-file limit
    for stale in (stale_file, stale_folder, stale_link):
        result = job(stale, base='none')
        assert result.returncode == 2, result.stderr
        assert not os.path.lexists(path) and upload_runs('failure') is False
    assert outside.read_bytes() == b'OLD'                        # removing a link leaves its target alone


def test_readme_clean_step_cannot_hide_changed_source_files_from_a_base_scan(tmp_path, scan_step):
    # A pull request that puts source code at the SARIF path does not get a scan without it: the scan stops.
    clean = readme_upload_job()['steps'][-3]
    assert clean == {'run': f'rm -rf {SARIF_EXAMPLE}'}
    root = pre_existing_only(tmp_path / 'check out')
    project(root, {f'{SARIF_EXAMPLE}/handler.py': 'import os\nos.system(cmd)'})
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'source code at the SARIF path')
    subprocess.run(['bash', '--noprofile', '--norc', '-e', '-c', clean['run']], cwd=root, check=True, timeout=60)
    result = scan_step(root, base='main', sarif=SARIF_EXAMPLE, cwd=root)
    assert result.returncode == 2, result.stderr
    assert 'no result issued' in result.stderr and result.stdout == '' and result.summary is None
    assert not os.path.lexists(root / SARIF_EXAMPLE)             # and there is nothing to upload
