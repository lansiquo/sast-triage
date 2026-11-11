"""Run the Action's scan shell step locally with real CLI results, without GitHub."""
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
