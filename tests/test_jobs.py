import json
import sqlite3
import subprocess

import pytest

import app
import worker
from job_store import JobStore
from analyzers import semgrep_runner as runner
from test_security import post


def payload():
    return dict(base_owner='lansiquo', base_repo='PR_Reviewer', head_owner='lansiquo',
                head_repo='PR_Reviewer', pr=1, head_sha='a' * 40, installation_id=80788483, base_sha='b'*40, base_ref='main')


def test_deduplication_persists_across_restarts(tmp_path):
    path = tmp_path / 'jobs.db'
    store = JobStore(path)
    key, created = store.enqueue(payload())
    assert created
    assert JobStore(path).enqueue(payload()) == (key, False)
    job = store.claim()
    assert job['id'] == key
    assert store.claim() is None
    store.finish(key)
    assert JobStore(path).enqueue(payload()) == (key, False)


def test_capacity_and_recovery(tmp_path):
    store = JobStore(tmp_path / 'jobs.db')
    key, _ = store.enqueue(payload(), capacity=1)
    changed = payload() | {'head_sha': 'b' * 40}
    with pytest.raises(OverflowError): store.enqueue(changed, capacity=1)
    store.claim()
    store.set_check(key, 123)
    store.recover()
    recovered = store.claim()
    assert recovered['check_id'] == 123
    assert recovered['attempts'] == 2
    store.retry(key, 'ConnectionError')
    assert store.claim() is None
    with store.connect() as db:
        row = db.execute('SELECT * FROM jobs').fetchone()
        assert row['state'] == 'queued'
        assert row['error'] == 'ConnectionError'


def test_concurrent_enqueue_is_atomic(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store = JobStore(tmp_path / 'jobs.db')
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: store.enqueue(payload()), range(10)))
    assert sum(created for _, created in results) == 1


def configure(monkeypatch):
    monkeypatch.setattr(app, 'MODE', 'durable')
    monkeypatch.setattr(app, 'ALLOWED_REPOSITORY', 'lansiquo/PR_Reviewer')
    monkeypatch.setattr(app, 'ALLOWED_INSTALLATION_ID', 80788483)


def test_webhook_queues_without_github_calls(tmp_path, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(app, 'JOB_DB', str(tmp_path / 'jobs.db'))
    side = {'sha': 'a' * 40, 'repo': {'owner': {'login': 'lansiquo'}, 'name': 'PR_Reviewer'}}
    body = json.dumps({'action': 'opened', 'number': 1, 'installation': {'id': 80788483},
                       'pull_request': {'head': side, 'base': side}}).encode()
    response = post(body, event='pull_request')
    assert response.status_code == 200
    assert response.json()['queued']
    response = post(body, event='pull_request')
    assert not response.json()['queued']
    monkeypatch.setattr(app, 'ALLOWED_REPOSITORY', 'lansiquo/Other')
    assert post(body, event='pull_request').status_code == 403


def test_token_request_is_scoped(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(app, '_create_app_jwt', lambda: 'fake')
    def send(url, **kwargs):
        assert kwargs['json'] == {'repositories': ['PR_Reviewer'],
            'permissions': {'contents': 'read', 'pull_requests': 'read', 'checks': 'write'}}
        class Response:
            status_code = 201
            def raise_for_status(self): pass
            def json(self): return {'token': 'fake-install-token'}
        return Response()
    monkeypatch.setattr(app.requests, 'post', send)
    assert app._get_installation_token(80788483) == 'fake-install-token'
    with pytest.raises(RuntimeError): app._get_installation_token(123)


def test_worker_reuses_reconciled_check(tmp_path, monkeypatch):
    configure(monkeypatch)
    store = JobStore(tmp_path / 'jobs.db')
    key, _ = store.enqueue(payload())
    job = store.claim()
    monkeypatch.setattr(app, '_get_installation_token', lambda *args: 'fake')
    monkeypatch.setattr(worker, 'find_existing_check', lambda *args: 123)
    scans = []
    monkeypatch.setattr(app, 'run_semgrep_pipeline', lambda *args, **kwargs: scans.append(args))
    worker.process_job(store, job)
    assert scans[0][-2] == 123
    with store.connect() as db:
        assert db.execute('SELECT state FROM jobs WHERE id=?', (key,)).fetchone()[0] == 'done'


def test_reconciliation_matches_app_and_exact_job(monkeypatch):
    monkeypatch.setattr(app, 'APP_ID', '42')
    monkeypatch.setattr(app, '_get_json', lambda *a, **kw: {'check_runs': [
        {'external_id': 'job', 'app': {'id': 99}, 'id': 1},
        {'external_id': 'other', 'app': {'id': 42}, 'id': 2},
        {'external_id': 'job', 'app': {'id': 42}, 'id': 3}]})
    assert worker.find_existing_check(payload(), 'job', 'fake') == 3


def test_superseded_commit_is_cancelled(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: {'head': {'sha': 'b' * 40}})
    complete = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: complete.append(a))
    p = payload()
    app.run_semgrep_pipeline(p['base_owner'], p['base_repo'], p['head_owner'], p['head_repo'],
                            p['pr'], p['head_sha'], p['installation_id'], p['base_owner'], p['base_repo'], 1, 'fake')
    assert complete[0][3] == 'cancelled'


def test_completion_failure_reaches_queue_for_retry(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: {'head': {'sha': 'b' * 40}})
    def fail(*a): raise ConnectionError('private-response')
    monkeypatch.setattr(app, 'complete_check_run', fail)
    with pytest.raises(ConnectionError):
        app.run_semgrep_pipeline('lansiquo', 'PR_Reviewer', 'lansiquo', 'PR_Reviewer', 1,
                                'a' * 40, 80788483, 'lansiquo', 'PR_Reviewer', 1, 'fake')


def test_container_restrictions(monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE', 'example/scanner@sha256:' + 'a' * 64)
    cmd = runner.docker_scan_command('/source', '/trusted.yaml', ['semgrep', '--config', '/trusted.yaml'], 'test')
    for arg in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--user=65532:65532', '--memory=768m', '--pids-limit=128', '--pull=never'):
        assert arg in cmd
    assert '/rules.yaml' in cmd
    assert not any('docker.sock' in part or 'PRIVATE_KEY' in part for part in cmd)
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE', 'example/scanner:latest')
    with pytest.raises(ValueError): runner.docker_scan_command('/source', '/trusted.yaml', [], 'test')


def test_worker_refuses_non_rootless_daemon(monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE', 'example/scanner@sha256:' + 'a' * 64)
    monkeypatch.setattr(runner.shutil, 'which', lambda _: '/docker')
    monkeypatch.setattr(runner.subprocess, 'run', lambda *a, **kw: subprocess.CompletedProcess([], 0, '["name=seccomp"]', ''))
    with pytest.raises(RuntimeError, match='rootless'): runner.verify_docker_sandbox()


def test_worker_readiness(tmp_path):
    store = JobStore(tmp_path / 'jobs.db')
    assert not store.ready()
    store.heartbeat()
    assert store.ready()
    with store.connect() as db:
        db.execute('UPDATE worker_health SET updated=0')
    assert not store.ready()


def test_bounded_scanner_timeout(tmp_path):
    import os
    import sys
    with pytest.raises(subprocess.TimeoutExpired):
        runner._bounded_container_run([sys.executable, '-c', 'import time; time.sleep(10)'],
                                      str(tmp_path), {'PATH': os.environ['PATH']}, 0.1)


def test_shared_queue_requires_private_group_directory(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SHARED_STATE', '1')
    with pytest.raises(RuntimeError, match='2770'):
        JobStore(tmp_path / 'missing' / 'jobs.db')
    tmp_path.chmod(0o2770)
    store = JobStore(tmp_path / 'jobs.db')
    import stat
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o660
    key, created = store.enqueue(payload())
    assert created
    assert JobStore(store.path).claim()['id'] == key
    store.path.chmod(0o666)
    with pytest.raises(RuntimeError, match='660'):
        JobStore(store.path)


def test_container_can_explicitly_select_opengrep(monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE', 'example/scanner@sha256:' + 'a' * 64)
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'opengrep')
    command = runner.docker_scan_command('/source', '/rules', ['semgrep', '--config', '/rules'], 'test')
    assert '--entrypoint=opengrep' in command
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'arbitrary-program')
    with pytest.raises(ValueError): runner.docker_scan_command('/source', '/rules', [], 'test')
