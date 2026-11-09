"""Scanner wrapper: refused configurations, timeouts and untrustworthy output. No scanner is started."""
import json
import subprocess

import pytest

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
            scan(tmp_path, monkeypatch, clean(), config='p/ci')
        rules = tmp_path / 'rules.yml'
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


def test_config_resolution(monkeypatch):
    monkeypatch.delenv('SEMGREP_CONFIG', raising=False)
    monkeypatch.delenv('SEMGRP_CONFIG', raising=False)
    for config, expected in (('p/ci', 'p/ci'), ('auto', 'auto'),
                             ('https://example.com/r.yml', 'https://example.com/r.yml'),
                             ('rules.yml', '/repo/rules.yml'), ('rules/a.yml, p/ci', '/repo/rules/a.yml,p/ci'),
                             ('  ', 'p/ci')):
        assert runner._resolve_config(config, '/repo') == expected, config
