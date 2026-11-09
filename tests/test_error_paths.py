"""Error and fail-closed paths in the webhook, GitHub helpers, scan pipeline and worker. No network: GitHub is stubbed."""
import io
import itertools
import json
import tarfile
import threading
import time
from contextlib import contextmanager
from email.utils import formatdate

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app
import worker
from analyzers import semgrep_runner as runner
from job_store import JobStore
from test_backend_boundaries import pipeline, response
from test_jobs import payload
from test_production_ops import deliver_push, pr_snapshot, push, setup
from test_security import post
from test_triage import finding

SIDE = {'sha': 'a' * 40, 'repo': {'owner': {'login': 'lansiquo'}, 'name': 'PR_Reviewer'}}


@contextmanager
def case(label):
    """Name the table row in any failure raised inside the block."""
    try:
        yield
    except BaseException as error:
        error.add_note(f'case: {label}')
        raise


def pr_event(action='opened', installation=80788483):
    return json.dumps({'action': action, 'number': 1, 'installation': {'id': installation},
                       'pull_request': {'head': SIDE, 'base': SIDE}}).encode()


@pytest.fixture
def local(monkeypatch):
    """Local mode with one scan slot; any scan that starts fails the test."""
    slot = threading.BoundedSemaphore(1)
    monkeypatch.setattr(app, 'MODE', 'local')
    monkeypatch.setattr(app, 'SCAN_SLOTS', slot)
    monkeypatch.setattr(app, 'run_semgrep_pipeline', lambda *a: pytest.fail('scan must not start'))
    return slot


@pytest.fixture
def durable(tmp_path, monkeypatch):
    return setup(tmp_path, monkeypatch)


# ---------- Webhook ----------

def test_local_webhook_refuses_or_ignores_without_scanning(local, monkeypatch):
    def no_token(*a): pytest.fail('no token may be requested')
    with monkeypatch.context() as m:
        m.setattr(app, '_get_installation_token', no_token)
        m.setattr(app, 'ALLOWED_INSTALLATION_ID', 80788483)
        assert post(pr_event(installation=1), event='pull_request').status_code == 403
        assert post(pr_event('closed'), event='pull_request').json() == {'ok': True, 'ignored': 'closed'}
        assert post(b'{}', event='issues').json() == {'ok': True, 'ignored_event': 'issues'}
        local.acquire()
        assert post(pr_event(), event='pull_request').status_code == 503   # scanner busy
        local.release()
    def fail(*a): raise requests.ConnectionError('private-response-sentinel')
    for failing in ('_get_installation_token', 'create_check_in_progress_with_fallback'):
        with case(failing), monkeypatch.context() as m:
            m.setattr(app, '_get_installation_token', lambda *a: 'fake')
            m.setattr(app, 'create_check_in_progress_with_fallback', lambda *a: ('o', 'r', 1))
            m.setattr(app, failing, fail)
            result = post(pr_event(), event='pull_request')
            assert result.status_code == 502 and 'private-response-sentinel' not in result.text
            assert local.acquire(blocking=False), 'scan slot was not released'
            local.release()


def test_durable_webhook_fails_closed(durable, monkeypatch):
    for setting, value in (('ALLOWED_REPOSITORY', ''), ('ALLOWED_INSTALLATION_ID', 0)):
        with case(setting), monkeypatch.context() as m:
            m.setattr(app, setting, value)
            assert post(b'{}').status_code == 503
    def full(*a, **k): raise OverflowError
    monkeypatch.setattr(JobStore, 'enqueue', full)
    for event, body in (('push', json.dumps(push()).encode()), ('pull_request', pr_event())):
        with case(event):
            assert post(body, event=event).status_code == 503   # queue full: GitHub redelivers


def test_health_and_readiness(local, durable, monkeypatch):
    client = TestClient(app.app)
    health = client.get('/health')
    assert health.json()['has_secret'] and 'testsecret' not in health.text
    monkeypatch.setattr(app, 'MODE', 'local')
    assert client.get('/ready').json() == {'ready': True, 'mode': 'local'}
    monkeypatch.setattr(app, 'MODE', 'durable')
    assert client.get('/ready').status_code == 503   # no worker heartbeat yet
    durable.heartbeat()
    assert client.get('/ready').json()['ready']
    monkeypatch.setattr(app, 'ALLOWED_INSTALLATION_ID', 0)
    assert client.get('/ready').status_code == 503


# ---------- GitHub helpers ----------

def test_app_credentials(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    monkeypatch.setattr(app, 'APP_PEM_PATH', '')
    monkeypatch.setattr(app, 'APP_PEM_INLINE', pem.replace('\n', '\\n'))
    monkeypatch.setattr(app, 'APP_ID', '')
    with pytest.raises(RuntimeError, match='GITHUB_APP_ID'):
        app._create_app_jwt()
    monkeypatch.setattr(app, 'APP_ID', '12345')
    claims = jwt.decode(app._create_app_jwt(), key.public_key(), algorithms=['RS256'])
    assert claims['iss'] == '12345' and claims['exp'] - claims['iat'] == 600
    monkeypatch.setattr(app, 'APP_PEM_INLINE', 'not a key')
    with pytest.raises(RuntimeError, match='not a valid PEM'):
        app._create_app_jwt()
    # Without an installation ID, only an explicitly configured token can be used.
    monkeypatch.setattr(app, 'MODE', 'local')
    monkeypatch.setattr(app, 'EXPLICIT_INSTALLATION_TOKEN', '')
    with pytest.raises(RuntimeError, match='No installation token'):
        app._get_installation_token(0)
    monkeypatch.setattr(app, 'EXPLICIT_INSTALLATION_TOKEN', 'explicit')
    assert app._get_installation_token(0) == 'explicit'


def test_github_requests_refresh_once_and_respect_rate_limits(monkeypatch):
    seen = []
    def send(method, url, headers, **k):
        seen.append(headers['Authorization'])
        return response(401 if len(seen) == 1 else 200)
    monkeypatch.setattr(app.requests, 'request', send)
    monkeypatch.setattr(app, '_get_installation_token', lambda i: 'fresh')
    assert app._gh_request('GET', 'https://api.github.com/x', 'stale', install_id=1).status_code == 200
    assert seen == ['Bearer stale', 'Bearer fresh']
    # A transient failure while refreshing reaches the worker's retry policy instead of becoming the old 401.
    monkeypatch.setattr(app.requests, 'request', lambda *a, **k: response(401))
    def down(i): raise requests.ConnectionError('down')
    monkeypatch.setattr(app, '_get_installation_token', down)
    with pytest.raises(requests.ConnectionError):
        app._gh_request('GET', 'https://api.github.com/x', 'stale', install_id=1)
    for headers, minimum in (({'Retry-After': formatdate(time.time() + 1200, usegmt=True)}, 1100),
                             ({'X-RateLimit-Remaining': '0'}, 60)):
        monkeypatch.setattr(app.requests, 'request', lambda *a, _h=headers, **k: response(403, **_h))
        with case(headers), pytest.raises(app.GitHubRateLimitError) as error:
            app._get_json('https://api.github.com/x', 'fake')
        assert error.value.retry_after >= minimum, headers


def test_check_run_falls_back_to_head_repo_only_on_permission_errors(monkeypatch):
    args = ('base', 'repo', 'fork', 'repo', 'a' * 40, 'name', 'title', 'summary', 'fake', 1)
    for status in (403, 404, 422, 500):
        def create(owner, repo, *a, _status=status):
            if owner == 'base':
                raise requests.HTTPError(response=response(_status))
            return 7
        monkeypatch.setattr(app, '_create_check_in_progress', create)
        with case(status):
            if status == 500:
                with pytest.raises(requests.HTTPError):
                    app.create_check_in_progress_with_fallback(*args)
            else:
                assert app.create_check_in_progress_with_fallback(*args) == ('fork', 'repo', 7)


def test_changed_file_list_stops_at_an_empty_page_and_fails_past_the_page_limit(monkeypatch):
    def full(page): return [{'filename': f'{page}_{i}.py'} for i in range(100)]
    pages = iter([full(1), []])
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: next(pages))
    assert len(app.list_changed_files('o', 'r', 1, 'fake', 1)) == 100
    requested = []
    monkeypatch.setattr(app, '_get_json', lambda url, token, params, install_id: requested.append(params['page']) or full(params['page']))
    with pytest.raises(RuntimeError, match='pagination limit'):
        app.list_changed_files('o', 'r', 1, 'fake', 1)
    assert requested == list(range(1, 31))


# ---------- Archive ----------

def tarball(*names):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 1
            tf.addfile(info, io.BytesIO(b'x'))
    return data.getvalue()


class Download:
    status_code = 200
    closed = False
    def __init__(self, body): self.body = body
    def raise_for_status(self): pass
    def iter_content(self, chunk_size): yield from (self.body[:10], self.body[10:])
    def close(self): self.closed = True


def test_archive_download(tmp_path, monkeypatch):
    def fetch(body, workdir):
        download = Download(body)
        monkeypatch.setattr(app, '_gh_request', lambda *a, **k: download)
        workdir.mkdir()
        try:
            return app.download_tarball('o', 'r', 'a' * 40, 'fake', 1, workdir)
        finally:
            assert download.closed
    root = fetch(tarball('repo-abc/main.py'), tmp_path / 'ok')
    assert root == tmp_path / 'ok' / 'repo-abc' and (root / 'main.py').read_text() == 'x'
    with pytest.raises(RuntimeError, match='Empty archive'):
        fetch(tarball(), tmp_path / 'empty')
    clock = itertools.count(0, 61)
    monkeypatch.setattr(app.time, 'monotonic', lambda: next(clock))
    with pytest.raises(RuntimeError, match='deadline'):
        fetch(tarball('repo/main.py'), tmp_path / 'slow')


# ---------- Pipeline ----------

def test_pipeline_refuses_paths_outside_the_snapshot_and_skips_non_python(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'MODE', 'local')
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: pytest.fail('must not scan'))
    for i, (name, expected) in enumerate((('../outside.py', 'failure'), ('ABSOLUTE', 'failure'), ('README.md', 'neutral'))):
        directory = tmp_path / f'case{i}'
        root = directory / 'root'
        root.mkdir(parents=True)
        (directory / 'outside.py').write_text('print(1)\n')   # exists, so only the path check can stop the scan
        changed = {str(directory / 'outside.py') if name == 'ABSOLUTE' else name: None}
        completed = []
        monkeypatch.setattr(app, 'download_tarball', lambda *a, _root=root: _root)
        monkeypatch.setattr(app, 'list_changed_files', lambda *a, _changed=changed: _changed)
        monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
        pipeline()
        assert completed[0][3] == expected, name


def test_rejected_annotations_are_dropped_not_the_result(tmp_path, monkeypatch):
    calls = []
    def complete(*a):
        calls.append(a)
        if len(calls) == 1:
            raise requests.HTTPError(response=response(422))
    monkeypatch.setattr(app, 'complete_check_run', complete)
    monkeypatch.setattr(app, 'MODE', 'local')
    (tmp_path / 'app.py').write_text('print(1)\n')
    monkeypatch.setattr(app, 'download_tarball', lambda *a: tmp_path)
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: {'app.py': {1}})
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: [finding('app.py', 1)])
    pipeline()
    assert [c[3] for c in calls] == ['failure', 'failure']
    assert len(calls[0][6]) == 1 and calls[1][6] == []


def test_completion_failure_is_raised_only_where_a_worker_can_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: {'head': {'sha': 'a' * 40}})
    (tmp_path / 'app.py').write_text('print(1)\n')
    monkeypatch.setattr(app, 'download_tarball', lambda *a: tmp_path)
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: {'app.py': {1}})
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: [])
    def down(*a): raise requests.ConnectionError('down')
    monkeypatch.setattr(app, 'complete_check_run', down)
    args = ('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake')
    monkeypatch.setattr(app, 'MODE', 'local')
    assert app.run_semgrep_pipeline(*args) == {'conclusion': 'success', 'scan_error': None}
    monkeypatch.setattr(app, 'MODE', 'durable')
    with pytest.raises(requests.ConnectionError):
        app.run_semgrep_pipeline(*args)


# ---------- Worker ----------

def test_worker_refuses_unscoped_or_unsandboxed_runs_and_foreign_jobs(durable, monkeypatch):
    monkeypatch.setattr(runner, 'verify_docker_sandbox', lambda: pytest.fail('must refuse before the sandbox check'))
    for setting, value, backend in (('MODE', 'local', 'docker'), ('ALLOWED_REPOSITORY', '', 'docker'),
                                    ('ALLOWED_INSTALLATION_ID', 0, 'docker'), (None, None, 'local')):
        with case(setting or f'backend={backend}'), monkeypatch.context() as m:
            m.setenv('PRSEC_SCANNER_BACKEND', backend)
            if setting:
                m.setattr(app, setting, value)
            with pytest.raises(RuntimeError, match='requires'):
                worker.run()
    monkeypatch.setattr(app, '_get_installation_token', lambda *a: pytest.fail('no token outside scope'))
    for change in ({'base_repo': 'Other'}, {'installation_id': 1}):
        durable.enqueue(payload() | change)
        with case(change), pytest.raises(RuntimeError, match='configured repository'):
            worker.process_job(durable, durable.claim())


def test_push_expansion_skips_closed_prs_and_refuses_out_of_scope_ones(durable, monkeypatch):
    monkeypatch.setattr(app, '_get_installation_token', lambda *a: 'fake')
    deliver_push(push())
    job = durable.claim()
    closed = pr_snapshot(2) | {'state': 'closed', 'base': None}   # unparseable, so it must be skipped
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: [pr_snapshot(1), closed])
    worker.process_job(durable, job)
    assert durable.claim()['payload']['pr'] == 1 and durable.claim() is None
    for sha, (field, value) in zip(('d' * 40, 'e' * 40),
                                   (('ref', 'develop'), ('repo', {'owner': {'login': 'other'}, 'name': 'PR_Reviewer'}))):
        deliver_push(push(sha=sha))
        job = durable.claim()
        escaped = pr_snapshot(3)
        escaped['base'] = escaped['base'] | {field: value}
        monkeypatch.setattr(app, '_get_json', lambda *a, _rows=[escaped], **k: _rows)
        with case(field), pytest.raises(ValueError, match='escaped requested scope'):
            worker.process_job(durable, job)
        assert durable.claim() is None, field


def test_reconciliation_and_push_enumeration_are_bounded(monkeypatch):
    monkeypatch.setattr(app, 'APP_ID', '42')
    pages = []
    other = {'external_id': 'other', 'app': {'id': 42}, 'id': 1}
    monkeypatch.setattr(app, '_get_json', lambda url, token, params, install_id:
                        pages.append(params['page']) or {'check_runs': [other] * 100})
    with pytest.raises(RuntimeError, match='pagination'):
        worker.find_existing_check(payload(), 'job', 'fake')
    assert pages == list(range(1, 11))
    closed = [pr_snapshot(n) | {'state': 'closed'} for n in range(1, 101)]
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: closed)
    job = {'id': 'push', 'payload': {'base_owner': 'lansiquo', 'base_repo': 'PR_Reviewer',
                                     'base_ref': 'main', 'installation_id': 80788483}}
    with pytest.raises(OverflowError, match='enumeration exceeded'):
        worker.expand_base_push(None, job, 'fake')
