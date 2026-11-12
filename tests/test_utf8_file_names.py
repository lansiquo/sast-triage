"""File names that are not valid UTF-8 stop the scan: Semgrep lists such a file as scanned but matches nothing in it.

Real Semgrep and real git on small trees that are written, scanned and never executed.
"""
import json
import os
import subprocess
import sys

import pytest

import scan_repo
from analyzers import semgrep_runner as runner
from test_scan_repo import ROOT, git

POPEN = b'import os\nos.popen(command)\n'           # py-os-popen: a P1 in runtime code
EVAL = b'const total = eval(req.body.preTax);\n'    # js-dangerous-eval: a P1 in runtime code


@pytest.fixture(autouse=True)
def local_scanner(monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')


def write(root, files):
    """Write {name as bytes: content} under root. Skips the test where the file system refuses the name."""
    for name, content in files.items():
        target = os.path.join(os.fsencode(root), name)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, 'wb') as handle:
                handle.write(content)
        except (OSError, UnicodeError) as error:    # macOS and Windows hold only names that are valid Unicode
            pytest.skip(f'this file system cannot hold the name {name!r}: {error}')
    return root


def branch(root, files):
    """A base commit on main with one clean file, then a feature branch that adds `files`."""
    write(root, {b'README.md': b'base\n', b'app.js': b'const n = 1;\n'})
    git(root, 'init', '-q', '-b', 'main')
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'base')
    git(root, 'switch', '-q', '-c', 'feature')
    write(root, files)
    git(root, 'add', '.')
    git(root, 'commit', '-q', '-m', 'feature')
    return root


@pytest.mark.parametrize('name,content,shown', [
    (b'bad\xe9.js', EVAL, 'bad\\xe9.js'),
    (b'caf\xff.py', POPEN, 'caf\\xff.py'),
    (b'src/d\xe9/handler.py', POPEN, 'src/d\\xe9/handler.py'),      # a folder in the path
], ids=['js-file', 'py-file', 'folder'])
def test_full_scan_exits_two_on_a_name_that_is_not_utf8_and_writes_no_output(tmp_path, capsys, name, content, shown):
    root = write(tmp_path / 'repo', {name: content, b'ok.js': b'const n = 1;\n'})
    summary, sarif = tmp_path / 'summary.md', tmp_path / 'out.sarif'
    assert scan_repo.main([str(root), '--json', '--markdown', str(summary), '--sarif', str(sarif)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ''                                       # no --json report, no Gate line
    assert captured.err == ('error: file names that are not valid UTF-8 cannot be scanned, no result issued: '
                            f'{shown}\n')
    assert not summary.exists() and not sarif.exists()


def test_the_error_spells_the_name_on_one_line_that_cannot_start_a_workflow_command(tmp_path, capsys):
    root = write(tmp_path / 'repo', {b'x\n::error file=a.py::\xff#[y].py': POPEN, b'caf\xe9.py': POPEN})
    assert scan_repo.main([str(root)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == ('error: file names that are not valid UTF-8 cannot be scanned, no result issued: '
                            'caf\\xe9.py, x\\x0a\\x3a\\x3aerror file\\x3da.py\\x3a\\x3a\\xff\\x23\\x5by\\x5d.py\n')


@pytest.mark.parametrize('name,shown', [
    (b'bad\xe9.js', 'bad\\xe9.js'),
    ('caf\udcff.py', 'caf\\xff.py'),                                # as Python reads the name from disk
    (b'src dir/a_b-c.9.PY', 'src dir/a_b-c.9.PY'),                  # letters, digits, space . _ - / stay
    ('café\udce9.py', 'caf\\xc3\\xa9\\xe9.py'),                # every other byte, valid UTF-8 or not
    (b'back\\slash:#[x]\x1b\r\n\t\x00\x7f', 'back\\x5cslash\\x3a\\x23\\x5bx\\x5d\\x1b\\x0d\\x0a\\x09\\x00\\x7f'),
    ('\ud800.py', '\\xed\\xa0\\x80.py'),                            # a lone surrogate that is not from disk
])
def test_ascii_name_writes_every_byte_outside_the_safe_set_as_hex(name, shown):
    assert runner.ascii_name(name) == shown


def test_a_name_is_utf8_only_when_its_bytes_on_disk_are_its_utf8_encoding(monkeypatch):
    assert runner.is_utf8_name('café.py') and runner.is_utf8_name('src dir/sample.py')
    assert not runner.is_utf8_name('caf\udce9.py')      # the byte e9 alone, read from disk with a surrogate escape
    assert not runner.is_utf8_name('\ud800.py')         # a lone surrogate, as JSON can carry one
    # In a Latin-1 locale Python reads the byte e9 as "é" with no escape, and Semgrep still matches nothing.
    monkeypatch.setattr(runner.os, 'fsencode', lambda name: name.encode('latin-1'))
    assert not runner.is_utf8_name('café.py') and runner.is_utf8_name('cafe.py')


def test_run_semgrep_refuses_a_path_that_is_not_utf8_before_the_scanner_starts(tmp_path, monkeypatch):
    write(tmp_path, {b'caf\xe9.py': POPEN})
    started = []
    def as_semgrep_answers(*a, **k):
        # Semgrep 1.79.0 on this file: exit status 0, the file listed as scanned, no result and no error.
        started.append(k.get('cmd'))
        return subprocess.CompletedProcess([], 0, json.dumps(
            {'results': [], 'errors': [], 'paths': {'scanned': ['caf\udce9.py']}}), '')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    monkeypatch.setattr(runner, '_bounded_container_run', as_semgrep_answers)
    for path, shown in (('caf\udce9.py', 'caf\\xe9.py'), ('\ud800.py', '\\xed\\xa0\\x80.py')):
        with pytest.raises(runner.SemgrepInvocationError) as error:
            runner.run_semgrep([path], str(tmp_path), config='/trusted/rules.yml')
        assert error.value.exit_code == 65 and f'File name is not valid UTF-8: {shown}' in str(error.value)
    assert started == []


@pytest.mark.parametrize('files', [
    {b'bad\xe9.js': EVAL},
    {b'docs/caf\xff.md': b'notes\n', b'web/app.js': EVAL},          # any changed name git lists, source file or not
], ids=['source-file', 'other-file'])
def test_base_exits_two_on_a_changed_name_that_is_not_utf8(tmp_path, capsys, files):
    root = branch(tmp_path / 'repo', files)
    summary, sarif = tmp_path / 'summary.md', tmp_path / 'out.sarif'
    assert scan_repo.main([str(root), '--base', 'main', '--json', '--markdown', str(summary),
                           '--sarif', str(sarif)]) == 2
    captured = capsys.readouterr()
    shown = runner.ascii_name(next(name for name in files if name != b'web/app.js'))
    assert captured.out == ''
    assert captured.err == ('error: cannot diff against main, no result issued.\n'
                            f'changed file names that are not valid UTF-8 cannot be scanned: {shown}\n')
    assert not summary.exists() and not sarif.exists()


def test_base_command_line_exits_two_without_a_traceback(tmp_path):
    root = branch(tmp_path / 'repo', {b'bad\xe9.js': EVAL})
    result = subprocess.run([sys.executable, 'scan_repo.py', str(root), '--base', 'main'], cwd=ROOT,
                            capture_output=True, timeout=300)
    assert result.returncode == 2 and result.stdout == b''
    assert b'no result issued' in result.stderr and b'bad\\xe9.js' in result.stderr
    assert b'Traceback' not in result.stderr


def test_base_exits_two_when_git_output_cannot_be_decoded(tmp_path, capsys):
    # The name is fine, but the diff of a Latin-1 file is not valid UTF-8 text.
    root = branch(tmp_path / 'repo', {b'legacy.py': b'# caf\xe9\n' + POPEN})
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == 'error: cannot diff against main, no result issued.\ngit diff output is not valid UTF-8\n'


def test_base_takes_a_changed_name_exactly_as_git_lists_it(tmp_path, capsys):
    # Read as text, the carriage return became a line feed: the name of the clean file beside it.
    root = branch(tmp_path / 'repo', {b'a\nb.py': b'x = 1\n', b'a\rb.py': POPEN})
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == ['a\nb.py', 'a\rb.py']
    assert [(f['path'], f['rule_id'], f['priority'], f['new']) for f in report['findings']] == [
        ('a\rb.py', 'py-os-popen', 'P1', True)]


def test_valid_utf8_names_are_still_scanned(tmp_path, capsys):
    files = {'café.py'.encode(): POPEN, b'src dir/sample.py': POPEN}
    expected = [('café.py', 2, 'py-os-popen', 'P1', True), ('src dir/sample.py', 2, 'py-os-popen', 'P1', True)]
    root = write(tmp_path / 'full', dict(files))
    assert scan_repo.main([str(root), '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == ['café.py', 'src dir/sample.py']
    assert [(f['path'], f['start_line'], f['rule_id'], f['priority'], f['new']) for f in report['findings']] == expected

    root = branch(tmp_path / 'changed', dict(files))
    assert scan_repo.main([str(root), '--base', 'main', '--json']) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['files'] == ['café.py', 'src dir/sample.py']
    assert [(f['path'], f['start_line'], f['rule_id'], f['priority'], f['new']) for f in report['findings']] == expected
