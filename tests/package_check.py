"""`make package-check`: build the command-line package offline, install it, and run its `sast-triage` command.

Not part of `make test`: pytest collects this file only when it is named, as the Makefile target
does. The build uses the build backend that is already installed (setuptools 77.0.3 or later) and
downloads nothing, so it fails in an environment without one.

The wheel is built from a copy of the checkout in a temporary folder, with
`python -m pip wheel --no-deps --no-build-isolation --no-index`, and installed into a fresh virtual
environment there. That environment gets Semgrep from the environment running the check, through a
.pth file, because it cannot download its own. Nothing is written to the checkout, and the temporary
folder is removed at the end.
"""
import json
import os
import shutil
import site
import subprocess
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / 'tests' / 'fixtures' / 'project'
# Left out of the copy that is built: version control, environments, caches, build output, local data and secrets.
NOT_COPIED = shutil.ignore_patterns('.git', '.venv', '.venv-*', 'venv', '__pycache__', '.pytest_cache', 'build',
                                    'dist', '*.egg-info', 'data', '*.sqlite3*', '.env', '.env.*', '*.pem', '*.key')
BUILD_OUTPUT = ('build', 'dist', '*.egg-info')


def run(command, cwd, env):
    return subprocess.run([str(part) for part in command], cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=600)


def build_output():
    """What a build in the checkout itself would leave there."""
    return sorted(path.name for pattern in BUILD_OUTPUT for path in ROOT.glob(pattern))


@pytest.fixture(scope='module')
def package():
    """The wheel built offline, and a fresh virtual environment outside the checkout with it installed."""
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    before = build_output()
    with tempfile.TemporaryDirectory(prefix='sast_triage_package_') as temporary:
        work = Path(temporary).resolve()
        outside = work / 'outside'   # the commands run here: not the checkout, and not the copy of it
        outside.mkdir()
        # Only PATH and the locale, no pip configuration, and proxies that refuse every connection:
        # a step that tried to download would fail instead of quietly using the network.
        env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL') if key in os.environ}
        env.update({'HOME': str(outside), 'PIP_CONFIG_FILE': os.devnull, 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
                    'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
                    'http_proxy': 'http://127.0.0.1:9', 'https_proxy': 'http://127.0.0.1:9',
                    'PRSEC_LOAD_DOTENV': '0', 'PYTHONDONTWRITEBYTECODE': '1'})

        shutil.copytree(ROOT, work / 'source', symlinks=True, ignore=NOT_COPIED)
        build = run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                     '-w', work / 'wheel', work / 'source'], outside, env)
        assert build.returncode == 0, (
            'The offline build failed. It needs the build backend installed already ('
            + ', '.join(project['build-system']['requires']) + '); nothing is downloaded.\n'
            + build.stdout + build.stderr)
        wheels = sorted((work / 'wheel').glob('*.whl'))
        assert len(wheels) == 1, wheels

        environment = work / 'venv'
        created = run([sys.executable, '-m', 'venv', '--without-pip', environment], outside, env)
        assert created.returncode == 0, created.stdout + created.stderr
        python = environment / 'bin' / 'python'
        purelib = run([python, '-c', 'import sysconfig; print(sysconfig.get_paths()["purelib"])'], outside, env)
        assert purelib.returncode == 0, purelib.stderr
        Path(purelib.stdout.strip(), 'environment_with_semgrep.pth').write_text(
            '\n'.join(site.getsitepackages()) + '\n', encoding='utf-8')
        # Without --no-deps: pip accepts the wheel only if its dependencies are installed already.
        installed = run([sys.executable, '-m', 'pip', '--python', python, 'install', '--no-index', wheels[0]],
                        outside, env)
        assert installed.returncode == 0, installed.stdout + installed.stderr

        # The scan finds the semgrep launcher beside its interpreter or on PATH: here, the one of this environment.
        scan_env = {**env, 'PATH': os.pathsep.join([str(Path(sys.executable).parent), env.get('PATH', os.defpath)])}
        yield SimpleNamespace(project=project, wheel=wheels[0], environment=environment, python=python,
                              command=environment / 'bin' / 'sast-triage', outside=outside, env=scan_env)
    assert build_output() == before, 'the check wrote build output to the checkout'


def test_wheel_builds_offline_with_the_package_metadata(package):
    project = package.project['project']
    assert package.wheel.name == f"sast_triage-{project['version']}-py3-none-any.whl"
    with zipfile.ZipFile(package.wheel) as wheel:
        info = f"sast_triage-{project['version']}.dist-info"
        metadata = wheel.read(f'{info}/METADATA').decode('utf-8').split('\n\n')[0].splitlines()
        entry_points = wheel.read(f'{info}/entry_points.txt').decode('utf-8')
        generator = wheel.read(f'{info}/WHEEL').decode('utf-8')
    assert 'Name: sast-triage' in metadata
    assert f"Version: {project['version']}" in metadata
    assert f"Requires-Python: {project['requires-python']}" in metadata
    assert 'License-Expression: MIT' in metadata
    assert [line for line in metadata if line.startswith('Requires-Dist: ')] == [
        f'Requires-Dist: {dependency}' for dependency in project['dependencies']]
    assert entry_points.split() == ['[console_scripts]', 'sast-triage', '=', 'scan_repo:main']
    assert 'Generator: setuptools ' in generator


def test_wheel_holds_only_the_command_line(package):
    """scan_repo, trusted_rules and analyzers, with the license: no App, worker, deploy/, tests or other files."""
    setuptools = package.project['tool']['setuptools']
    expected = {f'{module}.py' for module in setuptools['py-modules']}
    for name in setuptools['packages']:
        expected.update(path.relative_to(ROOT).as_posix() for path in (ROOT / name).rglob('*.py'))
    with zipfile.ZipFile(package.wheel) as wheel:
        names = set(wheel.namelist())
    info = f"sast_triage-{package.project['project']['version']}.dist-info/"
    assert {name for name in names if not name.startswith(info)} == expected
    assert {name[len(info):] for name in names if name.startswith(info)} == {
        'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt', 'licenses/LICENSE'}


def test_fresh_environment_holds_the_pinned_semgrep_and_the_installed_modules(package):
    """The command must run the installed package, not the checkout, with the Semgrep the requirements pin."""
    pin = next(line.strip() for line in (ROOT / 'requirements-cli.txt').read_text(encoding='utf-8').splitlines()
               if line.startswith('semgrep=='))
    result = run([package.python, '-c',
                  'import json, sys, importlib.metadata, scan_repo, trusted_rules, analyzers.triage, '
                  'analyzers.semgrep_runner\n'
                  'print(json.dumps({"semgrep": importlib.metadata.version("semgrep"), "prefix": sys.prefix, '
                  '"files": [scan_repo.__file__, trusted_rules.__file__, analyzers.triage.__file__, '
                  'analyzers.semgrep_runner.__file__]}))'], package.outside, package.env)
    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert f"semgrep=={seen['semgrep']}" == pin
    assert Path(seen['prefix']) == package.environment
    for file in seen['files']:
        assert Path(file).is_relative_to(package.environment), f'{file} is not the installed copy'
        assert not Path(file).is_relative_to(ROOT)


def test_installed_command_help_exits_0(package):
    result = run([package.command, '--help'], package.outside, package.env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith('usage: sast-triage ')


@pytest.mark.parametrize('arguments', [[], ['--json']])
def test_installed_command_scans_the_fixture_with_exit_1_and_prints_what_scan_repo_py_prints(package, arguments):
    """Run from outside the checkout: the planted P1 fails the gate, and the output is scan_repo.py's, byte for byte."""
    installed = run([package.command, FIXTURE, *arguments], package.outside, package.env)
    script = run([sys.executable, ROOT / 'scan_repo.py', FIXTURE, *arguments], ROOT, package.env)
    assert script.returncode == 1, script.stderr
    assert installed.returncode == 1, installed.stderr
    assert '[P1, new]' in script.stdout or '"priority": "P1"' in script.stdout
    assert installed.stdout == script.stdout
    assert installed.stderr == script.stderr


def test_installed_command_keeps_exit_0_for_a_passing_gate_and_exit_2_for_an_error(package, tmp_path):
    clean = tmp_path / 'clean'
    clean.mkdir()
    (clean / 'app.py').write_text('total = 1\n')
    passing = run([package.command, clean], package.outside, package.env)
    assert passing.returncode == 0, passing.stderr
    assert 'Gate: PASS' in passing.stdout

    missing = run([package.command, tmp_path / 'missing'], package.outside, package.env)
    script = run([sys.executable, ROOT / 'scan_repo.py', tmp_path / 'missing'], ROOT, package.env)
    assert missing.returncode == script.returncode == 2
    assert missing.stdout == script.stdout == ''
    assert 'not a directory' in missing.stderr
    # Only the program name differs: argparse takes it from the command that was run.
    assert missing.stderr == script.stderr.replace('scan_repo.py', 'sast-triage')
