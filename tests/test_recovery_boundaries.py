"""Real local queue/lock recovery; GitHub and container preflight remain mocked."""
from concurrent.futures import ThreadPoolExecutor
import io
import tarfile

import pytest

import app
import worker
from analyzers import semgrep_runner as runner
from job_store import JobStore
from test_jobs import configure, payload
from test_security import archive


class IdleWorker(Exception):
    pass


def test_worker_restart_recovers_without_duplicate_remote_check(tmp_path, monkeypatch, caplog):
    for failure_point in ['completion', 'persist_check']:
        with monkeypatch.context() as m:
            try:
                restart_after_failure(tmp_path / failure_point, m, caplog, failure_point)
            except AssertionError as error:
                raise AssertionError(f'failure_point={failure_point}: {error}') from error


def restart_after_failure(tmp_path, monkeypatch, caplog, failure_point):
    configure(monkeypatch)
    monkeypatch.setattr(app, 'APP_ID', '42')
    monkeypatch.setattr(app, 'JOB_DB', str(tmp_path / 'jobs.db'))
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'docker')
    monkeypatch.setattr(runner, 'verify_docker_sandbox', lambda: None)
    monkeypatch.setattr(app, '_get_installation_token', lambda *a: 'fake-token')
    store = JobStore(app.JOB_DB)
    key, _ = store.enqueue(payload())
    remote = []
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: {'check_runs': remote})
    def create(url, token, data, **kwargs):
        remote.append({'id': 99, 'external_id': data['external_id'], 'app': {'id': 42}})
        return remote[-1]
    monkeypatch.setattr(app, '_post_json', create)
    failures = []
    original_set = JobStore.set_check
    def persist(self, key, check_id):
        if failure_point == 'persist_check' and not failures:
            failures.append(True)
            raise ConnectionError('private-response-sentinel')
        original_set(self, key, check_id)
    monkeypatch.setattr(JobStore, 'set_check', persist)
    scans = []
    def scan(*args, **kwargs):
        scans.append(args)
        if failure_point == 'completion' and not failures:
            failures.append(True)
            raise ConnectionError('private-response-sentinel')
    monkeypatch.setattr(app, 'run_semgrep_pipeline', scan)
    def idle(_):
        raise IdleWorker()
    monkeypatch.setattr(worker.time, 'sleep', idle)
    with pytest.raises(IdleWorker):
        worker.run()
    with store.connect() as db:
        row = db.execute('SELECT * FROM jobs').fetchone()
        assert row['state'] == 'queued' and row['attempts'] == 1
        assert row['error'] == 'ConnectionError'
        assert row['check_id'] == (99 if failure_point == 'completion' else None)
        db.execute('UPDATE jobs SET retry_at=0')
    with pytest.raises(IdleWorker):
        worker.run()
    with store.connect() as db:
        row = db.execute('SELECT * FROM jobs').fetchone()
        assert row['state'] == 'done' and row['attempts'] == 2
        assert row['check_id'] == 99 and row['error'] is None
    assert len(remote) == 1
    assert remote[0]['external_id'] == key
    assert scans[-1][-2] == 99
    assert 'private-response-sentinel' not in caplog.text


def test_concurrent_claims_never_return_same_job(tmp_path):
    store = JobStore(tmp_path / 'jobs.db')
    expected = {store.enqueue(payload() | {'head_sha': f'{i:040x}'})[0] for i in range(20)}
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = list(pool.map(lambda _: store.claim(), range(32)))
    claimed = [job['id'] for job in jobs if job]
    assert len(claimed) == len(set(claimed)) == 20
    assert set(claimed) == expected


def test_head_changes_during_download_cancels_and_cleans_staging(monkeypatch):
    configure(monkeypatch)
    heads = iter(['a' * 40, 'b' * 40])
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: {'head': {'sha': next(heads)}})
    roots = []
    def download(*args):
        root = args[-1]
        roots.append(root)
        (root / 'main.py').write_text('print(1)')
        return root
    monkeypatch.setattr(app, 'download_tarball', download)
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: {'main.py': None})
    scans = []
    monkeypatch.setattr(app, 'run_semgrep', lambda **kw: scans.append(kw))
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
    app.run_semgrep_pipeline('lansiquo', 'PR_Reviewer', 'lansiquo', 'PR_Reviewer', 1,
                            'a' * 40, 80788483, 'lansiquo', 'PR_Reviewer', 99, 'fake')
    assert completed[0][3] == 'cancelled'
    assert not scans and roots and not roots[0].exists()


def test_multiple_archive_roots_fail_closed(tmp_path):
    with archive([('one/a.py', tarfile.REGTYPE, b'a'), ('two/b.py', tarfile.REGTYPE, b'b')]) as tf:
        with pytest.raises(RuntimeError, match='one root'):
            app._safe_extract_tar(tf, tmp_path)
    assert not (tmp_path / 'two').exists()


def test_truncated_archive_fails_before_success(tmp_path):
    member = tarfile.TarInfo('root/main.py')
    member.size = 100
    with tarfile.open(fileobj=io.BytesIO(member.tobuf() + b'abc'), mode='r:') as tf:
        with pytest.raises(tarfile.ReadError):
            app._safe_extract_tar(tf, tmp_path)
