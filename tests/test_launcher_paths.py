"""Semgrep installed in a folder whose path has a space, a tab or another character a path may hold.

pip writes the whole path of the environment's Python after "#!" on the first line of Semgrep's
launcher and of pysemgrep, the script the launcher starts for a scan. The kernel ends that name at
the first space or tab, so in such a folder neither script starts by itself.
"""
import os
import sys

import pytest

import scan_repo
from analyzers import semgrep_runner as runner

# Stands in for Semgrep's launcher and pysemgrep. Like the real launcher, `semgrep` starts pysemgrep
# from its own folder for a scan, and runs it inside itself only when given --legacy.
SCRIPT = '''
import json, os, sys
if os.path.basename(__file__) == "semgrep" and "--legacy" not in sys.argv:
    os.environ["PATH"] += os.pathsep + os.path.dirname(os.path.abspath(__file__))
    os.execvp("pysemgrep", ["pysemgrep", *sys.argv[1:]])
print(json.dumps({"results": [], "errors": [], "paths": {"scanned": ["main.py"]}}))
'''


def install(folder, first_line=None):
    """Lay out an environment's bin folder as pip leaves it: both scripts name its Python in full."""
    folder.mkdir(parents=True)
    os.symlink(sys.executable, folder / 'python')
    for name in ('semgrep', 'pysemgrep'):
        script = folder / name
        script.write_bytes((first_line or b'#!' + os.fsencode(folder / 'python')) + b'\n' + SCRIPT.encode())
        script.chmod(0o755)
    return folder


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'semgrep')
    monkeypatch.delenv('SEMGREP_BIN', raising=False)
    monkeypatch.setenv('PATH', '/nonexistent')   # only the environment's own launcher can be found
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'main.py').write_text('print(1)\n')
    return root


PATHS = {'space': 'runner temp', 'tab': 'runner\ttemp', 'non-ASCII and space': 'rünner tëmp',
         'no-break space': 'runner temp', 'non-ASCII': 'rünner', 'plain': 'runner'}


@pytest.mark.parametrize('name', PATHS.values(), ids=PATHS)
def test_the_scan_runs_semgrep_installed_under_any_path(tmp_path, monkeypatch, capsys, project, name):
    folder = install(tmp_path / name / 'sast-triage-venv' / 'bin')
    monkeypatch.setattr(runner.sys, 'executable', str(folder / 'python'))   # as the Action runs scan_repo.py
    assert scan_repo.main([str(project)]) == 0, capsys.readouterr().err
    assert 'Gate: PASS' in capsys.readouterr().out


# The kernel drops only the spaces and tabs around the interpreter's name, so every other character
# there stays part of it, and a carriage return is refused wherever it is.
UNSTARTABLE = {'CRLF': b'#!{bin}/python\r', 'carriage return inside': b'#!{bin}/py\rthon',
               'trailing vertical tab': b'#!{bin}/python\x0b', 'trailing no-break space': b'#!{bin}/python\xc2\xa0',
               'leading form feed': b'#!\x0c{bin}/python'}
UNUSABLE = {'missing interpreter': b'#!{bin}/missing python', 'quoted interpreter': b'#!"{bin}/python"',
            'folder as interpreter': b'#!{bin}', 'interpreter not executable': b'#!{bin}/plain file',
            **UNSTARTABLE, 'NUL': b'#!{bin}/python\x00'}


def refused(project, monkeypatch, capsys, folder, first_line=None):
    install(folder, first_line and first_line.replace(b'{bin}', os.fsencode(folder)))
    (folder / 'plain file').write_text('')   # not executable
    os.symlink(sys.executable, folder / 'py\rthon')   # so only the carriage return is wrong
    monkeypatch.setattr(runner.sys, 'executable', str(folder / 'python'))
    assert scan_repo.main([str(project)]) == 2
    assert 'No usable Semgrep launcher found' in capsys.readouterr().err


@pytest.mark.parametrize('first_line', UNUSABLE.values(), ids=UNUSABLE)
def test_a_launcher_that_cannot_start_is_still_refused_under_a_path_with_a_space(tmp_path, monkeypatch, capsys,
                                                                                  project, first_line):
    refused(project, monkeypatch, capsys, tmp_path / 'runner temp' / 'bin', first_line)


@pytest.mark.parametrize('first_line', UNSTARTABLE.values(), ids=UNSTARTABLE)
def test_a_launcher_the_kernel_cannot_start_is_refused_under_a_path_without_a_space(tmp_path, monkeypatch, capsys,
                                                                                     project, first_line):
    refused(project, monkeypatch, capsys, tmp_path / 'runner' / 'bin', first_line)


@pytest.mark.parametrize('name', ['runner temp', 'runner\u00a0temp'], ids=['space', 'no-break space'])
def test_a_first_line_longer_than_the_kernel_reads_is_still_refused_under_a_path_with_whitespace(
        tmp_path, monkeypatch, capsys, project, name):
    folder = tmp_path / name / ('x' * 200) / 'bin'
    assert len(os.fsencode(folder / 'python')) + 3 > 256   # "#!", the path and the newline
    refused(project, monkeypatch, capsys, folder)


@pytest.mark.parametrize('command', ['semgrep', 'opengrep'])
def test_only_semgrep_runs_its_python_command_line_inside_the_launcher(tmp_path, monkeypatch, project, command):
    folder = install(tmp_path / 'runner temp' / 'bin')
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', command)
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: str(folder / 'semgrep'))
    seen = []
    def process(cmd, **kwargs):
        seen.append(cmd)
        raise OSError('stop here')
    monkeypatch.setattr(runner, '_bounded_container_run', process)
    with pytest.raises(OSError, match='stop here'):
        runner.run_semgrep(['main.py'], str(project), config='/trusted/rules.yml')
    start = [str(folder / 'python'), str(folder / 'semgrep')] + (['--legacy'] if command == 'semgrep' else [])
    assert seen[0][:len(start)] == start and seen[0].count('--legacy') == (command == 'semgrep')
