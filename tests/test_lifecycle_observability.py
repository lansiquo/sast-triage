import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
import pytest
import requests
from fastapi.testclient import TestClient
import app
import worker
from job_store import JobStore
from test_jobs import configure, payload


def event(action='opened', base_sha='b'*40, base_ref='main'):
    return {'action':action,'number':1,'installation':{'id':80788483},
        'pull_request':{'head':{'sha':'a'*40,'repo':{'owner':{'login':'lansiquo'},'name':'PR_Reviewer'}},
        'base':{'sha':base_sha,'ref':base_ref,'repo':{'owner':{'login':'lansiquo'},'name':'PR_Reviewer'}}}}


def deliver(value, delivery='event-1'):
    body=json.dumps(value).encode()
    return TestClient(app.app).post('/webhook',content=body,headers={
        'X-GitHub-Event':'pull_request','X-GitHub-Delivery':delivery,
        'X-Hub-Signature-256':'sha256='+hmac.new(b'testsecret',body,hashlib.sha256).hexdigest()})


def setup_queue(tmp_path,monkeypatch):
    configure(monkeypatch);monkeypatch.setattr(app,'JOB_DB',str(tmp_path/'jobs.db'))
    return JobStore(app.JOB_DB)


def test_reopen_same_head_runs_once_after_completed_job(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch)
    first=deliver(event()).json();store.claim();store.finish(first['job_id'])
    reopened=deliver(event('reopened'),'reopen-1').json()
    assert reopened['queued'] and reopened['job_id']!=first['job_id']
    assert not deliver(event('reopened'),'reopen-1').json()['queued']
    assert JobStore(app.JOB_DB).claim()['id']==reopened['job_id']


def test_base_context_change_requeues_unchanged_head(tmp_path,monkeypatch):
    for sha,ref in [('c'*40,'main'),('b'*40,'release')]:
        with monkeypatch.context() as m:
            store=setup_queue(tmp_path/ref,m)
            first=deliver(event()).json();store.claim();store.finish(first['job_id'])
            changed=deliver(event('edited',sha,ref),'edit-1').json()
            assert changed['queued'] and changed['job_id']!=first['job_id'],(sha,ref)
            assert not deliver(event('edited',sha,ref),'edit-2').json()['queued'],(sha,ref)


def test_concurrent_reopen_redeliveries_are_atomic(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results=list(pool.map(lambda _:deliver(event('reopened'),'same-reopen').json(),range(8)))
    assert sum(r['queued'] for r in results)==1
    assert len({r['job_id'] for r in results})==1
    assert store.claim() is not None and store.claim() is None


def test_transient_retry_budget_survives_restarts(tmp_path):
    path=tmp_path/'jobs.db';store=JobStore(path);key,_=store.enqueue(payload())
    for _ in range(8):
        store=JobStore(path);assert store.claim() is not None
        store.retry(key,'ConnectionError')
        with store.connect() as db:db.execute('UPDATE jobs SET retry_at=0')
    store.recover();assert store.claim() is None
    with store.connect() as db:
        row=db.execute('SELECT * FROM jobs').fetchone()
        assert row['state']=='failed' and row['error']=='retry_exhausted:ConnectionError'


def test_permanent_http_error_stops_worker_retry_and_is_observable(tmp_path,monkeypatch):
    from analyzers import semgrep_runner
    store=setup_queue(tmp_path,monkeypatch);store.enqueue(payload())
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND','docker')
    monkeypatch.setattr(semgrep_runner,'verify_docker_sandbox',lambda:None)
    def forbidden(*a):
        response=requests.Response();response.status_code=403
        raise requests.HTTPError('SECRET-SENTINEL',response=response)
    monkeypatch.setattr(app,'_get_installation_token',forbidden)
    class Idle(Exception):pass
    def stop(_):raise Idle()
    monkeypatch.setattr(worker.time,'sleep',stop)
    with pytest.raises(Idle):worker.run()
    with store.connect() as db:
        row=db.execute('SELECT * FROM jobs').fetchone()
        assert row['state']=='failed' and row['attempts']==1 and row['error']=='HTTP_403'
    status=store.status()
    assert status['counts']['failed']==1 and status['needs_attention']
    result=TestClient(app.app).get('/ready')
    assert result.status_code==200 and result.json()['degraded']
    assert 'SECRET-SENTINEL' not in result.text and 'payload' not in result.text


def test_base_changes_during_scan_cancel_result(tmp_path,monkeypatch):
    configure(monkeypatch);(tmp_path/'main.py').write_text('print(1)')
    current={'head':{'sha':'a'*40},'base':{'sha':'b'*40,'ref':'main'}}
    states=iter([current,current,{**current,'base':{'sha':'c'*40,'ref':'main'}}])
    monkeypatch.setattr(app,'_get_json',lambda *a,**k:next(states))
    monkeypatch.setattr(app,'fetch_files',lambda *a:tmp_path)
    monkeypatch.setattr(app,'list_changed_files',lambda *a:{'main.py':None})
    monkeypatch.setattr(app,'run_semgrep',lambda **k:[])
    complete=[];monkeypatch.setattr(app,'complete_check_run',lambda *a:complete.append(a))
    app.run_semgrep_pipeline('lansiquo','PR_Reviewer','lansiquo','PR_Reviewer',1,'a'*40,80788483,
        'lansiquo','PR_Reviewer',99,'fake',expected_base_sha='b'*40,expected_base_ref='main')
    assert complete[0][3]=='cancelled'


def test_metadata_edit_does_not_duplicate_completed_check(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch)
    first=deliver(event()).json();store.claim();store.finish(first['job_id'])
    changed=event('edited');changed['pull_request']['title']='A different title'
    assert not deliver(changed,'title-edit').json()['queued']


def test_reopen_reconciliation_creates_one_check_per_real_event(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch);remote=[];contexts=[]
    monkeypatch.setattr(app,'APP_ID','42')
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    monkeypatch.setattr(app,'_get_json',lambda *a,**k:{'check_runs':remote})
    def create(url,token,data,**kwargs):
        item={'id':len(remote)+1,'external_id':data['external_id'],'app':{'id':42}}
        remote.append(item);return item
    monkeypatch.setattr(app,'_post_json',create)
    monkeypatch.setattr(app,'run_semgrep_pipeline',lambda *a,**k:contexts.append(k))
    first=deliver(event('reopened'),'reopen-a').json();worker.process_job(store,store.claim())
    assert not deliver(event('reopened'),'reopen-a').json()['queued']
    assert JobStore(app.JOB_DB).claim() is None
    second=deliver(event('reopened'),'reopen-b').json();worker.process_job(store,store.claim())
    assert len(remote)==2 and first['job_id']!=second['job_id']
    assert contexts==[{'expected_base_sha':'b'*40,'expected_base_ref':'main'}]*2


def test_explicit_recovery_is_atomic_and_reuses_check_id(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch);key,_=store.enqueue(payload());store.claim()
    store.set_check(key,99);store.fail(key,'HTTP_403')
    with ThreadPoolExecutor(max_workers=5) as pool:
        results=list(pool.map(lambda _:JobStore(app.JOB_DB).requeue_failed(key),range(8)))
    assert sum(results)==1
    job=store.claim();assert job['check_id']==99 and job['attempts']==1
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    monkeypatch.setattr(app,'_post_json',lambda *a,**k:pytest.fail('Must reuse existing Check'))
    monkeypatch.setattr(app,'run_semgrep_pipeline',lambda *a,**k:{'conclusion':'success','scan_error':None})
    worker.process_job(store,job)
    assert store.status()['counts']['done']==1 and not store.status()['needs_attention']


def test_scanner_error_is_terminal_but_security_findings_are_not(tmp_path,monkeypatch):
    store=setup_queue(tmp_path,monkeypatch)
    monkeypatch.setattr(app,'_get_installation_token',lambda *a:'fake')
    monkeypatch.setattr(worker,'find_existing_check',lambda *a:99)
    key,_=store.enqueue(payload());job=store.claim()
    monkeypatch.setattr(app,'run_semgrep_pipeline',lambda *a,**k:{'conclusion':'failure','scan_error':'SemgrepInvocationError'})
    worker.process_job(store,job)
    assert store.status()['counts']['failed']==1
    key2,_=store.enqueue(payload()|{'pr':2});job=store.claim()
    monkeypatch.setattr(app,'run_semgrep_pipeline',lambda *a,**k:{'conclusion':'failure','scan_error':None})
    worker.process_job(store,job)
    assert store.status()['counts']['done']==1


def test_pipeline_api_failure_deferred_to_worker_policy(monkeypatch):
    configure(monkeypatch)
    def fail(*a,**k):
        response=requests.Response();response.status_code=500
        raise requests.HTTPError('PRIVATE-SENTINEL',response=response)
    monkeypatch.setattr(app,'_get_json',fail)
    monkeypatch.setattr(app,'complete_check_run',lambda *a:pytest.fail('Do not complete during API outage'))
    with pytest.raises(requests.HTTPError):
        app.run_semgrep_pipeline('lansiquo','PR_Reviewer','lansiquo','PR_Reviewer',1,'a'*40,
            80788483,'lansiquo','PR_Reviewer',99,'fake')


def test_recovery_does_not_restart_exhausted_crashed_job(tmp_path):
    store=JobStore(tmp_path/'jobs.db');key,_=store.enqueue(payload());store.claim()
    with store.connect() as db:db.execute('UPDATE jobs SET attempts=8')
    store.recover();assert store.claim() is None
    assert store.status()['counts']['failed']==1
