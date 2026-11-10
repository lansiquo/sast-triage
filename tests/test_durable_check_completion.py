"""Durable mode: permanent GitHub errors complete the Check; fork PRs are read from the base repo.

HTTP is mocked at requests.request, so the real _gh_request, fetch_files
and complete_check_run code paths run without network access.
"""
import base64
import io

import pytest
import requests

import app
import worker
from test_jobs import payload
from test_lifecycle_observability import setup_queue

API = 'https://api.github.com'
BASE = 'lansiquo/PR_Reviewer'
FORK = 'contributor/PR_Reviewer'
HEAD, BASE_SHA, MERGE_BASE = 'a' * 40, 'b' * 40, 'c' * 40
PULL = {'state': 'open', 'head': {'sha': HEAD}, 'base': {'sha': BASE_SHA, 'ref': 'main'}}


def response(status, json_body=None, content=b''):
    r = requests.Response()
    r.status_code = status
    r.url = 'mock'
    r._content = content if json_body is None else requests.compat.json.dumps(json_body).encode()
    r.raw = io.BytesIO(r._content)
    return r


class FakeGitHub:
    """Answers the GitHub API calls one durable scan makes and records them."""

    def __init__(self, contents_status=200):
        self.contents_status = contents_status
        self.patch = '@@ -1 +1 @@\n-x\n+print(1)'   # the pull request changed line 1
        self.calls = []

    def __call__(self, method, url, **kwargs):
        path = url.removeprefix(API)
        self.calls.append((method, path, kwargs.get('json') or kwargs.get('params')))
        if method == 'GET' and path == f'/repos/{BASE}/pulls/1':
            return response(200, PULL)
        if method == 'GET' and path == f'/repos/{BASE}/contents/main.py':
            if self.contents_status != 200:
                return response(self.contents_status, {'message': 'Not Found'})
            data = b'print(1)\n'
            return response(200, {'type': 'file', 'path': 'main.py', 'size': len(data), 'encoding': 'base64',
                                  'content': base64.b64encode(data).decode()})
        if method == 'GET' and path == f'/repos/{BASE}/pulls/1/files':
            return response(200, [{'filename': 'main.py', 'status': 'modified', 'patch': self.patch}])
        if method == 'GET' and path == f'/repos/{BASE}/compare/{BASE_SHA}...{HEAD}':
            return response(200, {'merge_base_commit': {'sha': MERGE_BASE}})
        if method == 'PATCH' and path == f'/repos/{BASE}/check-runs/99':
            return response(200, {'id': 99})
        raise AssertionError(f'Unexpected GitHub call {method} {path}')

    def check_updates(self):
        return [body for method, path, body in self.calls if method == 'PATCH']

    def contents_requests(self):
        return [(path, params) for method, path, params in self.calls if '/contents/' in path]


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
        github.contents_status = status
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
        github.contents_status = status
        with pytest.raises(requests.HTTPError):
            scan_fork_pr()
            pytest.fail(f'HTTP {status} was not raised for retry')
        assert github.check_updates() == [], status


def test_worker_records_a_completed_permanent_failure_without_retrying(tmp_path, monkeypatch, github):
    store = setup_queue(tmp_path, monkeypatch)
    github.contents_status = 404
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


def test_fork_pr_files_are_read_from_the_base_repository(github, monkeypatch):
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: [])
    outcome = scan_fork_pr()
    assert github.contents_requests() == [(f'/repos/{BASE}/contents/main.py', {'ref': HEAD})]   # one file, no archive
    assert outcome == {'conclusion': 'success', 'scan_error': None}


FINDING = {'path': 'main.py', 'start_line': 1, 'end_line': 1, 'severity': 'HIGH', 'rule_id': 'py-rule',
           'title': 'Risk', 'message': 'Risk', 'fix': None, 'cwe': None, 'owasp': None}


def test_a_finding_on_a_changed_line_needs_no_base_version(github, monkeypatch):
    roots = []
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: roots.append(k['repo_root']) or [dict(FINDING)])
    outcome = scan_fork_pr()
    assert github.contents_requests() == [(f'/repos/{BASE}/contents/main.py', {'ref': HEAD})]
    assert not [p for m, p, params in github.calls if '/compare/' in p] and len(roots) == 1   # one scan
    assert outcome == {'conclusion': 'failure', 'scan_error': None}                           # new P1


def test_a_finding_on_an_untouched_line_is_checked_against_the_merge_base(github, monkeypatch):
    github.patch = '@@ -1,0 +2 @@\n+x = 2'          # the pull request only added line 2
    roots = []
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: roots.append(k['repo_root']) or [dict(FINDING)])
    outcome = scan_fork_pr()
    assert github.contents_requests() == [(f'/repos/{BASE}/contents/main.py', {'ref': HEAD}),
                                          (f'/repos/{BASE}/contents/main.py', {'ref': MERGE_BASE})]
    assert [(p, params) for m, p, params in github.calls if '/compare/' in p] == [
        (f'/repos/{BASE}/compare/{BASE_SHA}...{HEAD}', {'per_page': 1, 'page': 2})]
    assert len(roots) == 2 and roots[0] != roots[1]
    assert outcome == {'conclusion': 'success', 'scan_error': None}   # the base version has it: pre-existing
