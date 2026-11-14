"""Semgrep installed in a folder whose path has a space or a tab.

pip writes the whole path of the environment's Python after "#!" on the first line of Semgrep's
launcher and of pysemgrep, the script the launcher starts for a scan. The kernel ends that name at
the first space or tab, so in such a folder neither script starts by itself. Every other launcher
is accepted or refused exactly as at dc0c8be.
"""
import os
import re
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
         'non-ASCII': 'rünner', 'plain': 'runner'}


@pytest.mark.parametrize('name', PATHS.values(), ids=PATHS)
def test_the_scan_runs_semgrep_installed_under_any_path(tmp_path, monkeypatch, capsys, project, name):
    folder = install(tmp_path / name / 'sast-triage-venv' / 'bin')
    monkeypatch.setattr(runner.sys, 'executable', str(folder / 'python'))   # as the Action runs scan_repo.py
    assert scan_repo.main([str(project)]) == 0, capsys.readouterr().err
    assert 'Gate: PASS' in capsys.readouterr().out


# In "runner temp" the kernel starts "runner", and the launcher check accepts that name whenever it may be
# executed, as a folder may, though the kernel starts only a regular file.
NOT_A_FILE = {'folder': lambda path: path.mkdir(), 'link to a folder': lambda path: os.symlink(path.parent, path),
              'executable named pipe': lambda path: (os.mkfifo(path), path.chmod(0o755))}


@pytest.mark.parametrize('make', NOT_A_FILE.values(), ids=NOT_A_FILE)
@pytest.mark.parametrize('name', ['runner temp', 'runner\ttemp'], ids=['space', 'tab'])
def test_the_scan_runs_semgrep_when_the_name_before_the_space_is_not_a_file(tmp_path, monkeypatch, capsys, project,
                                                                            name, make):
    folder = install(tmp_path / name / 'sast-triage-venv' / 'bin')
    make(tmp_path / 'runner')
    monkeypatch.setattr(runner.sys, 'executable', str(folder / 'python'))
    assert runner._launcher_is_usable(str(folder / 'semgrep'))   # accepted, as before
    assert scan_repo.main([str(project)]) == 0, capsys.readouterr().err
    assert 'Gate: PASS' in capsys.readouterr().out


# How the launcher starts when the name before the space is a file or nothing, as at 7de5f48: by itself (None)
# when the kernel can start that name, or else through the interpreter its whole first line names.
BESIDE = {'executable file': (lambda path: os.symlink(sys.executable, path), False),
          'file that is not executable': (lambda path: path.write_text(''), True), 'nothing': (lambda path: None, True)}


@pytest.mark.parametrize('make, spaced', BESIDE.values(), ids=BESIDE)
def test_a_launcher_starts_as_before_when_the_name_before_the_space_is_a_file_or_nothing(tmp_path, monkeypatch,
                                                                                        project, make, spaced):
    folder = install(tmp_path / 'runner temp' / 'sast-triage-venv' / 'bin')
    make(tmp_path / 'runner')
    monkeypatch.setenv('SEMGREP_BIN', str(folder / 'semgrep'))
    assert runner._ensure_semgrep_available() == str(folder / 'semgrep')
    assert runner._spaced_interpreter(str(folder / 'semgrep')) == (str(folder / 'python') if spaced else None)


# Under a path with a space these were refused at dc0c8be, and the new route takes none of them.
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


# Launchers that started at dc0c8be, whose check ends the interpreter's name at any whitespace: env
# reads the carriage return as a separator, and the kernel finds an interpreter whose name has one.
WORKING = {'env -S with CRLF': b'#!/usr/bin/env -S {bin}/python\r', 'interpreter named python CR': b'#!{bin}/python\r',
           'interpreter named python CR #x': b'#!{bin}/python\r#x'}


@pytest.mark.skipif(not os.access('/usr/bin/env', os.X_OK), reason='needs /usr/bin/env')
@pytest.mark.parametrize('first_line', WORKING.values(), ids=WORKING)
def test_a_launcher_that_started_at_dc0c8be_still_runs_as_it_did(tmp_path, monkeypatch, capsys, project, first_line):
    folder = install(tmp_path / 'runner' / 'bin', first_line.replace(b'{bin}', os.fsencode(tmp_path / 'runner' / 'bin')))
    for name in ('python\r', 'python\r#x'):
        os.symlink(sys.executable, folder / name)
    monkeypatch.setattr(runner.sys, 'executable', str(folder / 'python'))
    assert runner._spaced_interpreter(str(folder / 'semgrep')) is None   # started by itself, as before
    assert scan_repo.main([str(project)]) == 0, capsys.readouterr().err
    assert 'Gate: PASS' in capsys.readouterr().out


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


def accepted_at_dc0c8be(executable):
    """dc0c8be's launcher check, kept here to compare every decision with."""
    try:
        with open(executable, "rb") as source:
            first_line = source.readline(4096)
        if first_line.startswith(b"#!"):
            interpreter = first_line[2:].decode("utf-8").strip().split()[0]
            return os.path.isabs(interpreter) and os.access(interpreter, os.X_OK)
        return True  # Native executable; launch errors remain fatal.
    except (OSError, UnicodeError, IndexError):
        return False


def decision(check):
    try:
        return check()
    except ValueError:   # a NUL in the interpreter's name, as at dc0c8be
        return ValueError


CHARACTERS = ' \t\r\x0b\x0c\x1c\x1d\x1e\x1f\x85\xa0\u1680\u2000\u2003\u200a\u2028\u2029\u202f\u205f\u3000'
FOLDERS = ['runner', 'runner temp', 'runner\ttemp', 'runner  temp', 'runner\u00a0temp', 'runner\u3000temp']


def probe(tmp_path):
    """Yield (first line, the existing executable it names in full or None, line end), short and long."""
    for index, (name, long) in enumerate((name, long) for name in FOLDERS for long in (False, True)):
        folder = tmp_path / str(index) / name / ('x' * 200 if long else '') / 'bin'
        executables = ['python', 'python\r#x', *(f'python{c}' for c in CHARACTERS), *(f'py{c}thon' for c in CHARACTERS)]
        folder.mkdir(parents=True)
        for executable in executables:
            os.symlink(sys.executable, folder / executable)
        (folder / 'plain file').write_text('')   # not executable
        (folder / 'some dir').mkdir()
        named = {os.fsencode(folder / executable): str(folder / executable) for executable in executables}
        bin_ = os.fsencode(folder)
        lines = [b'#!' + path for path in named] + [b'#!' + c.encode() + bin_ + b'/python' for c in CHARACTERS]
        lines += [b'#!' + bin_ + b'/' + name for name in (b'missing', b'plain file', b'some dir', b'py\xffthon',
                                                         b'py\x00thon', b'python\x00', b'python -E', b'python\rpass')]
        lines += [b'#!"' + bin_ + b'/python"', b'#!' + bin_, b'#!/usr/bin/env -S ' + bin_ + b'/python\r',
                  b'#!/usr/bin/env -S ' + bin_ + b'/python', b'#!runner temp/python', b'#!', b'\x7fELF']
        for line in lines:
            yield line, named.get(line[2:]), b'\n'
        yield b'#!' + bin_ + b'/python', None, b''   # no newline: the whole file is this line


def test_every_decision_is_dc0c8be_s_except_a_space_or_tab_in_an_existing_interpreter_path(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'semgrep')
    launcher = tmp_path / 'launcher'
    changed = compared = 0
    for line, interpreter, end in probe(tmp_path / 'probe'):
        launcher.write_bytes(line + end + (b'print(1)\n' if end else b''))
        launcher.chmod(0o755)
        monkeypatch.setenv('SEMGREP_BIN', str(launcher))
        before = decision(lambda: accepted_at_dc0c8be(str(launcher)))
        def discovered():
            try:
                return runner._ensure_semgrep_available() == str(launcher)
            except runner.SemgrepInvocationError:
                return False
        after = decision(discovered)
        # The one intended change: dc0c8be refused it only for a space or tab in the existing executable it names.
        if (before is False and interpreter and re.search('[ \t]', interpreter) and '\r' not in interpreter
                and len(line + end) <= 256):
            assert after is True and runner._spaced_interpreter(str(launcher)) == interpreter, line
            changed += 1
        else:
            assert after == before, line
            if before is True:
                assert runner._spaced_interpreter(str(launcher)) is None, line   # started as at dc0c8be
            compared += 1
    assert changed >= 50 and compared >= 252
