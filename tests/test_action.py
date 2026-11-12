"""Run the Action's shell steps locally with real CLI results, without GitHub."""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def action(tmp_path):
    steps = yaml.safe_load((ROOT / 'action.yml').read_text())['runs']['steps']
    script = next(step['run'] for step in steps if step['name'] == 'Scan')
    runner_temp = tmp_path / 'runner temp'
    runner_temp.mkdir()
    # Reuse the installed test environment; the suite must not pip install or use the network.
    (runner_temp / 'sast-triage-venv').symlink_to(sys.prefix, target_is_directory=True)
    env = {key: os.environ[key] for key in ('HOME', 'PATH', 'LANG', 'TZ') if key in os.environ}
    env.update({'RUNNER_TEMP': str(runner_temp), 'GITHUB_ACTION_PATH': str(ROOT),
                'SAST_BASE': 'none', 'PRSEC_LOAD_DOTENV': '0', 'PRSEC_MODE': 'local',
                'PRSEC_SCANNER_BACKEND': 'local'})

    def run(directory, summary):
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                                cwd=ROOT, env={**env, 'SAST_PATH': str(directory),
                                               'GITHUB_STEP_SUMMARY': str(summary)},
                                capture_output=True, text=True, timeout=300)
        return result, summary.read_bytes() if summary.exists() else b''

    return run


def project(tmp_path, source):
    directory = tmp_path / 'project'
    directory.mkdir()
    (directory / 'app.js').write_text(source)
    return directory


@pytest.mark.parametrize('source,code,gate', [
    ('const total = 1;\n', 0, b'**Gate: PASS**'),
    ('const total = eval(req.body.preTax);\n', 1, b'**Gate: FAIL**'),
])
def test_action_keeps_completed_scan_exit_code_and_summary(tmp_path, action, source, code, gate):
    directory = project(tmp_path, source)
    expected = tmp_path / 'expected.md'
    cli = subprocess.run([sys.executable, str(ROOT / 'scan_repo.py'), str(directory),
                          '--markdown', str(expected)], cwd=ROOT,
                         capture_output=True, text=True, timeout=300)
    assert cli.returncode == code, cli.stderr
    result, summary = action(directory, tmp_path / 'summary.md')
    assert result.returncode == code, result.stderr
    assert gate in summary
    assert summary == expected.read_bytes()


@pytest.mark.parametrize('source,code', [
    ('const total = 1;\n', 0),
    ('const total = eval(req.body.preTax);\n', 1),
])
def test_action_error_does_not_repeat_previous_summary(tmp_path, action, source, code):
    first, summary = action(project(tmp_path, source), tmp_path / 'first.md')
    assert first.returncode == code, first.stderr
    assert b'**Gate:' in summary

    second, summary = action(tmp_path / 'missing', tmp_path / 'second.md')
    assert second.returncode == 2, second.stderr
    assert 'not a directory' in second.stderr
    assert summary == b'', 'scan error appended the previous invocation\'s summary'


def test_action_error_without_previous_report_issues_no_summary(tmp_path, action):
    result, summary = action(tmp_path / 'missing', tmp_path / 'summary.md')
    assert result.returncode == 2, result.stderr
    assert 'not a directory' in result.stderr
    assert summary == b''


# GitHub starts every step in the workspace, which is the scanned checkout. A Python started there with
# -m or -c puts that folder first on its import path; -I (isolated mode) leaves it out. A script run by
# its path gets the script's own folder there instead, so it must be one of the Action's own files.
def run_scripts():
    steps = yaml.safe_load((ROOT / 'action.yml').read_text())['runs']['steps']
    return {step['name']: step['run'] for step in steps if 'run' in step}


def run_step(name, workspace, runner_temp, **variables):
    """Run one step as GitHub's `shell: bash` does, from the checkout. A variable given as None is left unset."""
    env = {key: os.environ[key] for key in ('HOME', 'PATH', 'LANG', 'TZ') if key in os.environ}
    env.update({'RUNNER_TEMP': str(runner_temp), **variables})
    env = {key: value for key, value in env.items() if value is not None}
    return subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', run_scripts()[name]],
                          cwd=workspace, env=env, capture_output=True, text=True, timeout=300)


def plant_modules(workspace, markers, *names):
    """Put modules in the checkout that only record that they ran."""
    markers.mkdir()
    for name in names:
        (workspace / f'{name}.py').write_text(f'open({str(markers / name)!r}, "w").close()\n')


def ran(markers):
    return sorted(marker.name for marker in markers.iterdir())


def test_action_python_calls_cannot_import_from_the_scanned_checkout():
    calls = []
    for step, script in run_scripts().items():
        for line in script.replace('\\\n', ' ').splitlines():
            words = [word.strip('"\'') for word in line.split()]
            start = next((i for i, word in enumerate(words) if Path(word).name.startswith('python')), None)
            if start is not None:
                calls.append((step, words[start:]))
    assert len(calls) >= 3, f'expected the venv, pip and scan_repo.py calls, found {calls}'
    for step, words in calls:
        command = f'{step}: `{" ".join(words)}`'
        options = []
        target = None
        for word in words[1:]:
            if word in ('-m', '-c') or not word.startswith('-'):
                target = word
                break
            options.append(word)
        if target in ('-m', '-c', None):
            assert '-I' in options, f'{command} needs -I, or it imports from the scanned checkout'
        else:
            assert target.startswith('$GITHUB_ACTION_PATH/'), f'{command} runs a script outside the Action'


def test_install_step_runs_no_module_from_the_scanned_checkout(tmp_path):
    workspace, runner_temp, action_path = tmp_path / 'workspace', tmp_path / 'runner_temp', tmp_path / 'action'
    for directory in (workspace, runner_temp, action_path):
        directory.mkdir()
    # Nothing to install, so the real venv and pip commands run without the network.
    (action_path / 'requirements-cli.txt').write_text('')
    markers = tmp_path / 'markers'
    plant_modules(workspace, markers, 'venv', 'pip', 'ensurepip', 'logging', 'shutil', 'sysconfig')

    result = run_step('Install the scanner', workspace, runner_temp,
                      GITHUB_ACTION_PATH=str(action_path), PIP_NO_INDEX='1')

    assert ran(markers) == [], f'the install step ran {ran(markers)} from the scanned checkout'
    assert result.returncode == 0, result.stderr
    assert (runner_temp / 'sast-triage-venv' / 'pyvenv.cfg').is_file()


def scan_checkout(tmp_path, workspace, **variables):
    """Run the Scan step from the checkout with the installed test environment: its result and summary."""
    runner_temp = tmp_path / 'runner_temp'
    runner_temp.mkdir()
    (runner_temp / 'sast-triage-venv').symlink_to(sys.prefix, target_is_directory=True)
    summary = tmp_path / 'summary.md'
    result = run_step('Scan', workspace, runner_temp, GITHUB_ACTION_PATH=str(ROOT),
                      GITHUB_STEP_SUMMARY=str(summary), SAST_PATH='.', SAST_BASE='none', SAST_TIMEOUT='',
                      SAST_SARIF='', PRSEC_LOAD_DOTENV='0', PRSEC_MODE='local', PRSEC_SCANNER_BACKEND='local',
                      **variables)
    return result, summary.read_bytes() if summary.exists() else b''


# A job can set PYTHONPATH for its own code, and a relative entry such as "." is then the scanned checkout.
@pytest.mark.parametrize('variables', [{}, {'PYTHONPATH': '.'}], ids=['default', 'PYTHONPATH'])
def test_scan_step_runs_no_module_from_the_scanned_checkout(tmp_path, variables):
    workspace = project(tmp_path, 'const total = eval(req.body.preTax);\n')
    markers = tmp_path / 'markers'
    plant_modules(workspace, markers, 'argparse', 'tempfile', 'analyzers', 'trusted_rules', 'certifi')

    result, summary = scan_checkout(tmp_path, workspace, **variables)

    assert ran(markers) == [], f'the scan step ran {ran(markers)} from the scanned checkout'
    assert result.returncode == 1, result.stderr
    assert b'**Gate: FAIL**' in summary


# The scan step's Python reads no PYTHON* variable, so the report's encoding comes from the locale alone.
@pytest.mark.parametrize('lang', ['C.UTF-8', None], ids=['LANG=C.UTF-8', 'LANG-unset'])
def test_scan_step_writes_a_utf8_summary_without_python_variables(tmp_path, lang):
    workspace = project(tmp_path, 'const total = eval(req.body.preTax);\n')

    result, summary = scan_checkout(tmp_path, workspace, LANG=lang)

    assert result.returncode == 1, result.stderr
    assert '**Gate: FAIL** \u2014 1 new P1 finding'.encode('utf-8') in summary
