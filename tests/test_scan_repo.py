"""Full-repository scan CLI: real Semgrep on a small fixture tree that is written, scanned and never executed."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import scan_repo
from analyzers import semgrep_runner as runner

ROOT = Path(__file__).resolve().parent.parent

# path: source. Each file would leave a marker if anything ever ran it.
PROJECT = {
    'server.js': "require('fs').writeFileSync('EXECUTED', '');\nconst total = eval(req.body.preTax);",
    'routes/redirect.ts': 'export const go = (req, res) => res.redirect(req.query.url);',
    'tools/report.py': "open('EXECUTED', 'w')\nimport hashlib\nhashlib.md5(b'x')",
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
    assert report['conclusion'] == 'failure' and report['rules'] == 29
    assert [(f['priority'], f['new'], f['path'], f['start_line'], f['rule_id']) for f in report['findings']] == [
        ('P1', True, 'server.js', 2, 'js-dangerous-eval'),
        ('P1', True, 'tools/report.py', 3, 'py-weak-md5'),
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
    assert '5 Python, JavaScript and TypeScript files, 29 service-owned rules.' in out
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
    assert '3 Python, JavaScript and TypeScript files, 29 service-owned rules.' in result.stdout
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
        'src/legacy.py': "import hashlib\nhashlib.md5(b'old')",                 # pre-existing P1, file edited
        'src/untouched.py': "import hashlib\nhashlib.md5(b'old')",              # never scanned
        'tests/test_cache.py': "import pickle\npickle.loads(b'')",             # moved into runtime code
        'web/app.js': 'const n = 1;',
    })
    git(tmp_path, 'init', '-q', '-b', 'main')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'base')
    git(tmp_path, 'switch', '-q', '-c', 'feature')
    project(tmp_path, {'src/legacy.py': "import hashlib\nhashlib.md5(b'old')\nimport os\nos.system(cmd)",
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
        ('src/legacy.py', 2, 'py-weak-md5'): ('P1', False),               # untouched line: pre-existing
        ('web/app.js', 2, 'js-dangerous-eval'): ('P1', True),
        ('src/cache.py', 2, 'py-insecure-deserialization-pickle-loads'): ('P1', True),   # test -> runtime
    }


def test_base_passes_when_only_pre_existing_findings_remain(tmp_path, capsys):
    root = repository(tmp_path)
    git(root, 'switch', '-q', 'main')
    git(root, 'switch', '-q', '-c', 'docs-only')
    project(root, {'src/legacy.py': "import hashlib\nhashlib.md5(b'old')\n# reviewed"})
    git(root, 'commit', '-q', '-am', 'comment')
    assert scan_repo.main([str(root), '--base', 'main']) == 0
    out = capsys.readouterr().out
    assert '[P1, pre-existing] src/legacy.py:2  py-weak-md5' in out and '**Gate: PASS**' in out
    assert 'New: on lines changed since main.' in out


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
        ('src/moved.py', 2, 'py-weak-md5', 'P1', False)]

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
    assert '0 Python, JavaScript and TypeScript files, 29 service-owned rules.' in out
    assert 'No supported Python, JavaScript or TypeScript files to scan.' in out and 'Gate' not in out
