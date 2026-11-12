"""Scanner wrapper: refused configurations, timeouts and untrustworthy output. No scanner is started."""
import json
import subprocess

import pytest

import app
import scan_repo
from analyzers import semgrep_runner as runner
from test_error_paths import case

PINNED = 'example/scanner@sha256:' + 'a' * 64


def result(path='main.py', severity='ERROR'):
    return {'check_id': 'trusted-rule', 'path': path, 'start': {'line': 1}, 'end': {'line': 1},
            'extra': {'severity': severity, 'message': 'Risk', 'metadata': {}}}


def clean(*results, scanned=('main.py',)):
    return {'results': list(results), 'errors': [], 'paths': {'scanned': list(scanned)}}


def scan(tmp_path, monkeypatch, output=None, returncode=0, config='/trusted/rules.yml'):
    """Run run_semgrep against a fake scanner process; return (findings, command)."""
    (tmp_path / 'main.py').write_text('print(1)\n')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    seen = []
    def process(*a, **k):
        seen.append(k.get('cmd', a[0] if a else None))
        if isinstance(output, BaseException):
            raise output
        return subprocess.CompletedProcess([], returncode, json.dumps(output), '')
    monkeypatch.setattr(runner, '_bounded_container_run', process)
    findings = runner.run_semgrep(['main.py'], str(tmp_path), config=config)
    return findings, seen[0]


def test_only_known_backends_and_scanner_commands_run(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv('PRSEC_SCANNER_COMMAND', 'bash')
        with pytest.raises(ValueError, match='Unsupported scanner command'):
            runner._ensure_semgrep_available()
        with pytest.raises(ValueError, match='Unsupported scanner command'):
            runner.docker_scan_command('/scan', '/rules.yaml', ['semgrep', '--config', 'x'], 'name')
        with pytest.raises(ValueError, match='Unsupported scanner command'):
            scan(tmp_path, monkeypatch, clean())   # stubs the launcher, so run_semgrep's own check is what fires
    with monkeypatch.context() as m:
        m.setenv('PRSEC_SCANNER_BACKEND', 'podman')
        with pytest.raises(ValueError, match='Unsupported scanner backend'):
            scan(tmp_path, monkeypatch, clean())
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'opengrep')   # Opengrep rejects the metrics flag; nothing else changes
    _, cmd = scan(tmp_path, monkeypatch, clean())
    assert '--metrics=off' not in cmd and '--disable-nosem' in cmd and '--config' in cmd


def test_timeouts_and_untrustworthy_output_are_scanner_errors(tmp_path, monkeypatch):
    with pytest.raises(runner.SemgrepInvocationError) as error:
        scan(tmp_path, monkeypatch, subprocess.TimeoutExpired('semgrep', 5))
    assert error.value.exit_code == 124
    for output, returncode, reason in (({'results': [], 'errors': []}, 0, 'target coverage'),
                                       (clean(result('other.py')), 1, 'Unexpected finding path'),
                                       (clean(), 1, 'contradicts')):
        with case(reason), pytest.raises(runner.SemgrepInvocationError, match=reason):
            scan(tmp_path, monkeypatch, output, returncode)


# A coverage report ("paths") the scanner could send in place of {"scanned": [every staged file]}.
NOT_AN_OBJECT = {'null': None, 'list': ['main.py'], 'string': 'main.py', 'number': 7}
NO_FILE_LIST = {'empty object': {}, 'scanned null': {'scanned': None}, 'scanned string': {'scanned': 'main.py'},
                'scanned object': {'scanned': {'main.py': True}}, 'scanned mixed list': {'scanned': ['main.py', 7]}}


def fake_scanner(monkeypatch, paths):
    """Make the scanner process answer with a clean result whose coverage report is `paths`."""
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    monkeypatch.setattr(runner, '_bounded_container_run', lambda *a, **k: subprocess.CompletedProcess(
        [], 0, json.dumps({**clean(), 'paths': paths}), ''))


@pytest.mark.parametrize('paths', [*NOT_AN_OBJECT.values(), *NO_FILE_LIST.values()],
                         ids=[*NOT_AN_OBJECT, *NO_FILE_LIST])
def test_a_malformed_coverage_report_is_a_scanner_error(tmp_path, monkeypatch, paths):
    with pytest.raises(runner.SemgrepInvocationError, match='Scanner did not report target coverage') as error:
        scan(tmp_path, monkeypatch, {**clean(), 'paths': paths})
    assert error.value.exit_code == 65


@pytest.mark.parametrize('paths', NOT_AN_OBJECT.values(), ids=NOT_AN_OBJECT)
def test_command_line_exits_with_two_on_a_malformed_coverage_report(tmp_path, monkeypatch, capsys, paths):
    (tmp_path / 'main.py').write_text('print(1)\n')
    fake_scanner(monkeypatch, paths)
    assert scan_repo.main([str(tmp_path)]) == 2   # not a traceback, which exits with 1 like a failed gate
    captured = capsys.readouterr()
    assert 'scan incomplete, no result issued' in captured.err
    assert 'Scanner did not report target coverage' in captured.err
    assert 'Traceback' not in captured.err and 'Gate' not in captured.out


@pytest.mark.parametrize('paths', NOT_AN_OBJECT.values(), ids=NOT_AN_OBJECT)
def test_app_check_fails_as_a_scanner_error_on_a_malformed_coverage_report(tmp_path, monkeypatch, paths):
    (tmp_path / 'main.py').write_text('print(1)\n')
    fake_scanner(monkeypatch, paths)
    monkeypatch.setattr(app, 'MODE', 'local')
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: {'main.py': {1}})
    monkeypatch.setattr(app, 'fetch_files', lambda *a: tmp_path)
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
    outcome = app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake')
    assert outcome == {'conclusion': 'failure', 'scan_error': 'SemgrepInvocationError'}
    assert len(completed) == 1 and completed[0][3] == 'failure' and 'Scan incomplete' in completed[0][5]


def test_empty_request_and_non_file_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, '_bounded_container_run', lambda *a, **k: pytest.fail('must not run'))
    assert runner.run_semgrep([], str(tmp_path), config='/trusted/rules.yml') == []
    (tmp_path / 'pkg.py').mkdir()
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    with pytest.raises(ValueError, match='must be a file'):
        runner.run_semgrep(['pkg.py'], str(tmp_path), config='/trusted/rules.yml')


def test_severity_names_and_floor(tmp_path, monkeypatch):
    output = clean(*(result(severity=s) for s in ('BLOCKER', 'ERROR', 'WARN', 'INFO')))
    for floor, kept in (('HIGH', ['CRITICAL', 'HIGH']), ('off', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])):
        monkeypatch.setenv('PRSEC_SEMGREP_MIN_SEVERITY', floor)
        findings, _ = scan(tmp_path, monkeypatch, output, 1)
        assert [f['severity'] for f in findings] == kept, floor


def test_docker_sandbox_preconditions(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE', PINNED)
    with monkeypatch.context() as m:
        m.setenv('PRSEC_SCANNER_BACKEND', 'docker')
        m.setenv('DOCKER_HOST', 'unix:///run/user/1000/docker.sock')
        with pytest.raises(ValueError, match='exactly one service-owned local ruleset'):
            scan(tmp_path, monkeypatch, clean(), config='/trusted/missing.yml')
        rules = tmp_path.parent / f'{tmp_path.name}-rules.yml'
        rules.write_text('rules: []')
        envs = []
        m.setattr(runner, '_bounded_container_run', lambda cmd, cwd, env, timeout:
                  envs.append(env) or subprocess.CompletedProcess(cmd, 0, json.dumps(clean()), ''))
        m.setattr(runner.subprocess, 'run', lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, '', ''))
        assert runner.run_semgrep(['main.py'], str(tmp_path), config=str(rules)) == []
        assert envs[0]['DOCKER_HOST'] == 'unix:///run/user/1000/docker.sock'
    # The worker's preflight needs Docker, a digest-pinned image, and that image already present.
    monkeypatch.setattr(runner.shutil, 'which', lambda _: None)
    with pytest.raises(RuntimeError, match='digest-pinned'):
        runner.verify_docker_sandbox()
    monkeypatch.setattr(runner.shutil, 'which', lambda _: '/docker')
    with monkeypatch.context() as m:
        m.setenv('PRSEC_SCANNER_IMAGE', 'example/scanner:latest')
        with pytest.raises(RuntimeError, match='digest-pinned'):
            runner.verify_docker_sandbox()
    calls = []
    def docker(cmd, **k):
        calls.append(cmd[1])
        if cmd[1] == 'image':
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0, '["name=rootless"]', '')
    monkeypatch.setattr(runner.subprocess, 'run', docker)
    with pytest.raises(subprocess.CalledProcessError):
        runner.verify_docker_sandbox()
    assert calls == ['info', 'image']


def test_launcher_check(tmp_path):
    native = tmp_path / 'native'
    native.write_bytes(b'\x7fELF')
    stale = tmp_path / 'stale'
    stale.write_text('#!/no/such/python\n')
    relative = tmp_path / 'relative'
    relative.write_text('#!python\n')
    assert runner._launcher_is_usable(str(native))
    assert not runner._launcher_is_usable(str(stale))
    assert not runner._launcher_is_usable(str(relative))
    assert not runner._launcher_is_usable(str(tmp_path / 'missing'))


def test_only_one_local_rule_file_outside_the_scanned_tree_configures_the_scanner(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, '_bounded_container_run', lambda *a, **k: pytest.fail('scanner must not start'))
    monkeypatch.setenv('SEMGREP_CONFIG', '/trusted/rules.yml')   # no environment fallback
    (tmp_path / 'main.py').write_text('print(1)\n')
    (tmp_path / 'rules.yml').write_text('rules: []\n')         # inside the scanned tree
    (tmp_path / 'ruledir.yaml').mkdir()
    refused = (None, '', 'p/ci', 'p/default', 'r/python.lang.security.audit.eval', 'auto', 'semgrep-auto',
               'https://semgrep.dev/c/p/ci', 'http://rules.example/r.yml', 'rules.yml', './rules.yml',
               'rules/a.yml', '/trusted/a.yml,/trusted/b.yml', '/trusted/rules.json', ' /trusted/rules.yml',
               str(tmp_path / 'rules.yml'), str(tmp_path / 'sub' / '..' / 'rules.yml'), str(tmp_path / 'ruledir.yaml'))
    for config in refused:
        with case(config), pytest.raises(ValueError, match='Scanner rules must'):
            runner.run_semgrep(['main.py'], str(tmp_path), config=config)
    with pytest.raises(ValueError, match='Scanner rules must'):
        runner.run_semgrep([], str(tmp_path), config='auto')   # refused even with nothing to scan


def test_semgrep_runs_with_metrics_off_and_only_the_local_rule_file(tmp_path, monkeypatch):
    (tmp_path / 'main.py').write_text('print(1)\n')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    calls = []
    monkeypatch.setattr(runner, '_bounded_container_run',
                        lambda **k: calls.append(k) or subprocess.CompletedProcess([], 0, json.dumps(clean()), ''))
    rules = tmp_path.parent / f'{tmp_path.name}-trusted.yml'
    assert runner.run_semgrep(['main.py'], str(tmp_path), config=str(rules)) == []
    cmd, env = calls[0]['cmd'], calls[0]['env']
    assert cmd.count('--config') == 1 and cmd[cmd.index('--config') + 1] == str(rules)
    assert {'--metrics=off', '--disable-version-check', '--disable-nosem'} <= set(cmd)
    assert env['SEMGREP_SEND_METRICS'] == 'off' and env['SEMGREP_ENABLE_VERSION_CHECK'] == '0'
