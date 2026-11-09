"""Durable mode: permanent GitHub errors complete the Check; fork PRs are read from the base repo.

HTTP is mocked at requests.request, so the real _gh_request, download_tarball
and complete_check_run code paths run without network access.
"""
import io
import tarfile

import pytest
import requests

import app
import worker
from test_jobs import payload
from test_lifecycle_observability import setup_queue

API = 'https://api.github.com'
BASE = 'lansiquo/PR_Reviewer'
FORK = 'contributor/PR_Reviewer'
HEAD, BASE_SHA = 'a' * 40, 'b' * 40
PULL = {'state': 'open', 'head': {'sha': HEAD}, 'base': {'sha': BASE_SHA, 'ref': 'main'}}


def response(status, json_body=None, content=b''):
    r = requests.Response()
    r.status_code = status
    r.url = 'mock'
    r._content = content if json_body is None else requests.compat.json.dumps(json_body).encode()
    r.raw = io.BytesIO(r._content)
    return r


def tarball(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tf:
        root = tarfile.TarInfo('repo-' + HEAD[:7]); root.type = tarfile.DIRTYPE; root.mode = 0o755
        tf.addfile(root)
        for name, text in files.items():
            info = tarfile.TarInfo(f'repo-{HEAD[:7]}/{name}'); data = text.encode(); info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeGitHub:
    """Answers the GitHub API calls one durable scan makes and records them."""

    def __init__(self, tarball_status=200):
        self.tarball_status = tarball_status
        self.calls = []

    def __call__(self, method, url, **kwargs):
        path = url.removeprefix(API)
        self.calls.append((method, path, kwargs.get('json')))
        if method == 'GET' and path == f'/repos/{BASE}/pulls/1':
            return response(200, PULL)
        if method == 'GET' and '/tarball/' in path:
            if self.tarball_status != 200:
                return response(self.tarball_status, {'message': 'Not Found'})
            return response(200, content=tarball({'main.py': 'print(1)\n'}))
        if method == 'GET' and path == f'/repos/{BASE}/pulls/1/files':
            return response(200, [{'filename': 'main.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-x\n+print(1)'}])
        if method == 'PATCH' and path == f'/repos/{BASE}/check-runs/99':
            return response(200, {'id': 99})
        raise AssertionError(f'Unexpected GitHub call {method} {path}')

    def check_updates(self):
        return [body for method, path, body in self.calls if method == 'PATCH']

    def tarball_paths(self):
        return [path for method, path, _ in self.calls if '/tarball/' in path]


@pytest.fixture
def github(monkeypatch):
    from test_jobs import configure
    configure(monkeypatch)
    fake = FakeGitHub()
    monkeypatch.setattr(requests, 'request', fake)
    return fake


def scan_fork_pr():
    return app.run_semgrep_pipeline('lansiquo', 'PR_Reviewer', 'contributor', 'PR_Reviewer', 1, HEAD,
                                    80788483, 'lansiquo', 'PR_Reviewer', 99, 'fake',
                                    expected_base_sha=BASE_SHA, expected_base_ref='main')


def test_permanent_api_error_completes_the_check_as_failure(github):
    for status in [403, 404, 410, 422]:
        github.calls.clear()
        github.tarball_status = status
        outcome = scan_fork_pr()
        assert outcome == {'conclusion': 'failure', 'scan_error': f'HTTP_{status}'}, status
        updates = github.check_updates()
        assert len(updates) == 1, status
        [update] = updates
        assert update['status'] == 'completed' and update['conclusion'] == 'failure', status
        assert f'HTTP {status}' in update['output']['summary'], status
        assert 'No clean result was issued' in update['output']['summary'], status


def test_transient_api_error_still_leaves_the_check_to_the_worker_retry(github):
    for status in [500, 502]:
        github.calls.clear()
        github.tarball_status = status
        with pytest.raises(requests.HTTPError):
            scan_fork_pr()
            pytest.fail(f'HTTP {status} was not raised for retry')
        assert github.check_updates() == [], status


def test_worker_records_a_completed_permanent_failure_without_retrying(tmp_path, monkeypatch, github):
    store = setup_queue(tmp_path, monkeypatch)
    github.tarball_status = 404
    monkeypatch.setattr(app, '_get_installation_token', lambda *a: 'fake')
    store.enqueue(payload() | {'head_owner': 'contributor'})
    job = store.claim()
    store.set_check(job['id'], 99)
    job['check_id'] = 99
    worker.process_job(store, job)
    with store.connect() as db:
        row = db.execute('SELECT state, error FROM jobs').fetchone()
    assert (row['state'], row['error']) == ('failed', 'scan_error:HTTP_404')
    assert github.check_updates()[-1]['conclusion'] == 'failure'


def test_fork_pr_snapshot_is_downloaded_from_the_base_repository(github, monkeypatch):
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: [])
    outcome = scan_fork_pr()
    assert github.tarball_paths() == [f'/repos/{BASE}/tarball/{HEAD}']
    assert outcome == {'conclusion': 'success', 'scan_error': None}
