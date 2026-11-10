"""Controlled GitHub integration tests: no external requests or Check mutations."""
import time
import pytest
import requests
import app
from job_store import JobStore
from test_jobs import configure, payload


def response(status, **headers):
    r = requests.Response(); r.status_code = status
    r.headers.update(headers); r._content = b'private-response-sentinel'
    return r


def test_api_rate_limit_becomes_safe_retry(monkeypatch):
    for status, headers, minimum in [
        (429, {'Retry-After': '900'}, 900),
        (403, {'X-RateLimit-Remaining':'0', 'X-RateLimit-Reset':str(time.time()+1800)}, 1700),
        (429, {'Retry-After':'not-a-date'}, 60),
        (429, {'Retry-After':'inf'}, 60),
    ]:
        with monkeypatch.context() as m:
            m.setattr(app.requests, 'request', lambda *a, **k: response(status, **headers))
            with pytest.raises(app.GitHubRateLimitError) as error:
                app._get_json('https://api.github.com/example', 'fake')
                pytest.fail(f'no rate limit for {status} {headers}')
        assert error.value.retry_after >= minimum, (status, headers)
        assert 'private-response' not in str(error.value), (status, headers)


def test_rate_limit_pauses_all_jobs_and_survives_restart(tmp_path):
    path=tmp_path/'jobs.db';store=JobStore(path)
    key,_=store.enqueue(payload());store.enqueue(payload()|{'pr':2});store.claim()
    store.retry(key, 'GitHubRateLimitError', retry_after=900)
    restarted=JobStore(path);restarted.recover()
    assert restarted.claim() is None
    with restarted.connect() as db:
        assert db.execute('SELECT retry_at FROM worker_backoff').fetchone()[0] > time.time()+890
        db.execute('UPDATE worker_backoff SET retry_at=0')
    assert restarted.claim()['payload']['pr']==2


def test_refresh_failure_logs_no_private_message(monkeypatch, caplog):
    monkeypatch.setattr(app.requests, 'request', lambda *a, **k: response(401))
    def fail(*a): raise RuntimeError('private-response-sentinel')
    monkeypatch.setattr(app, '_get_installation_token', fail)
    assert app._gh_request('GET','https://api.github.com/example','fake',install_id=1).status_code==401
    assert 'private-response-sentinel' not in caplog.text


def pipeline():
    return app.run_semgrep_pipeline('lansiquo','PR_Reviewer','lansiquo','PR_Reviewer',1,
        'a'*40,80788483,'lansiquo','PR_Reviewer',99,'fake')


def test_pipeline_rate_limit_does_not_attempt_completion(monkeypatch):
    configure(monkeypatch)
    def limited(*a, **k): raise app.GitHubRateLimitError(response(429),900)
    monkeypatch.setattr(app,'_get_json',limited)
    monkeypatch.setattr(app,'complete_check_run',lambda *a:pytest.fail('Must not call API during cooldown'))
    with pytest.raises(app.GitHubRateLimitError):pipeline()


def test_local_rate_limit_completes_the_check_as_failed(monkeypatch):
    # Local mode has no worker to retry, so the Check must not stay in progress.
    monkeypatch.setattr(app,'MODE','local')
    monkeypatch.setattr(app,'list_changed_files',lambda *a:{'main.py':None})
    def limited(*a, **k): raise app.GitHubRateLimitError(response(403,**{'Retry-After':'60'}),60)
    monkeypatch.setattr(app,'fetch_files',limited)
    monkeypatch.setattr(app,'run_semgrep',lambda **k:pytest.fail('Must not scan without the files'))
    completed=[];monkeypatch.setattr(app,'complete_check_run',lambda *a:completed.append(a))
    assert pipeline()=={'conclusion':'failure','scan_error':'rate_limited'}
    assert len(completed)==1 and completed[0][3]=='failure' and 'rate limit' in completed[0][5]


def test_close_or_new_commit_during_scan_cancels_result(tmp_path, monkeypatch):
    configure(monkeypatch);(tmp_path/'main.py').write_text('print(1)')
    monkeypatch.setattr(app,'fetch_files',lambda *a:tmp_path)
    monkeypatch.setattr(app,'list_changed_files',lambda *a:{'main.py':None})
    for last in [{'state':'closed','head':{'sha':'a'*40}}, {'state':'open','head':{'sha':'b'*40}}]:
        states=iter([{'head':{'sha':'a'*40}}]*2+[last])
        scans=[];completions=[]
        with monkeypatch.context() as m:
            m.setattr(app,'_get_json',lambda *a,**k:next(states))
            m.setattr(app,'run_semgrep',lambda **k:scans.append(k) or [])
            m.setattr(app,'complete_check_run',lambda *a:completions.append(a))
            pipeline()
        assert len(scans)==1 and completions[0][3]=='cancelled', last


def test_missing_changed_python_file_is_failure(tmp_path,monkeypatch):
    monkeypatch.setattr(app,'MODE','local')
    monkeypatch.setattr(app,'fetch_files',lambda *a:tmp_path)
    monkeypatch.setattr(app,'list_changed_files',lambda *a:{'missing.py':None})
    monkeypatch.setattr(app,'run_semgrep',lambda **k:pytest.fail('Must not scan incomplete snapshot'))
    completed=[];monkeypatch.setattr(app,'complete_check_run',lambda *a:completed.append(a))
    pipeline();assert completed[0][3]=='failure'


def test_removed_files_excluded_but_modified_files_preserved(monkeypatch):
    monkeypatch.setattr(app,'_get_json',lambda *a,**k:[{'filename':'deleted.py','status':'removed'},{'filename':'main.py','status':'modified'}])
    assert app.list_changed_files('o','r',1,'fake',1)=={'main.py':None}


def test_worker_applies_rate_limit_to_persistent_queue(tmp_path,monkeypatch):
    import worker
    from analyzers import semgrep_runner
    configure(monkeypatch);monkeypatch.setattr(app,'JOB_DB',str(tmp_path/'jobs.db'))
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND','docker')
    monkeypatch.setattr(semgrep_runner,'verify_docker_sandbox',lambda:None)
    store=JobStore(app.JOB_DB);store.enqueue(payload());store.enqueue(payload()|{'pr':2})
    def limited(*a):raise app.GitHubRateLimitError(response(429),900)
    monkeypatch.setattr(app,'_get_installation_token',limited)
    class Idle(Exception):pass
    def stop(_):raise Idle()
    monkeypatch.setattr(worker.time,'sleep',stop)
    with pytest.raises(Idle):worker.run()
    with store.connect() as db:
        rows=db.execute('SELECT attempts,state FROM jobs').fetchall()
        assert sorted(row['attempts'] for row in rows)==[0,1]
        assert all(row['state']=='queued' for row in rows)
        assert db.execute('SELECT retry_at FROM worker_backoff').fetchone()[0]>time.time()+890


def test_malformed_empty_file_list_is_not_a_clean_pr(monkeypatch):
    monkeypatch.setattr(app,'_get_json',lambda *a,**k:{})
    with pytest.raises(RuntimeError,match='Invalid PR file list'):
        app.list_changed_files('o','r',1,'fake',1)
