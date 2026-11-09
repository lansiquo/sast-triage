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


def test_command_line_exit_status(tmp_path):
    root = project(tmp_path, {'app.js': 'eval(req.query.code);'})
    result = subprocess.run([sys.executable, str(ROOT / 'scan_repo.py'), str(root)], cwd=ROOT,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 1, result.stderr
    assert '[P1, new] app.js:1  js-dangerous-eval' in result.stdout
