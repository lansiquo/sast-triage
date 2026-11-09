import copy
import json
import subprocess
import pytest
import requests
import app
from analyzers import semgrep_runner as runner


def finding():
    return {'check_id':'trusted-rule','path':'main.py','start':{'line':1},'end':{'line':1},
            'extra':{'severity':'ERROR','message':'Risk','metadata':{}}}


def scan_output(tmp_path,monkeypatch,result):
    (tmp_path/'main.py').write_text('print(1)\n')
    monkeypatch.setenv('PRSEC_MODE','local');monkeypatch.setenv('PRSEC_SCANNER_BACKEND','local')
    monkeypatch.setenv('PRSEC_SEMGREP_MIN_SEVERITY','HIGH')
    monkeypatch.setattr(runner,'_ensure_semgrep_available',lambda:'/fake/scanner')
    data={'results':[result],'errors':[],'paths':{'scanned':['main.py']}}
    monkeypatch.setattr(runner,'_bounded_container_run',lambda **k:subprocess.CompletedProcess([],0,json.dumps(data),''))
    return runner.run_semgrep(['main.py'],str(tmp_path),config='/trusted/rules.yaml')


def test_transient_token_refresh_error_is_not_reported_as_permanent_401(monkeypatch):
    unauthorized=requests.Response();unauthorized.status_code=401
    monkeypatch.setattr(app.requests,'request',lambda *a,**k:unauthorized)
    def refresh(*a):
        response=requests.Response();response.status_code=503
        raise requests.HTTPError('PRIVATE-SENTINEL',response=response)
    monkeypatch.setattr(app,'_get_installation_token',refresh)
    with pytest.raises(requests.HTTPError) as raised:app._gh_request('GET','https://api.github.com/example','fake',install_id=1)
    assert raised.value.response.status_code==503


def test_unconfirmed_container_cleanup_cannot_return_success(tmp_path,monkeypatch):
    repo=tmp_path/'repo';repo.mkdir();(repo/'main.py').write_text('print(1)\n')
    rules=tmp_path/'rules.yaml';rules.write_text('rules: []\n')
    monkeypatch.setenv('PRSEC_MODE','durable');monkeypatch.setenv('PRSEC_SCANNER_BACKEND','docker')
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE','example/scanner@sha256:'+'a'*64)
    data={'results':[],'errors':[],'paths':{'scanned':['main.py']}}
    monkeypatch.setattr(runner,'_bounded_container_run',lambda *a,**k:subprocess.CompletedProcess([],0,json.dumps(data),''))
    monkeypatch.setattr(runner.subprocess,'run',lambda *a,**k:subprocess.CompletedProcess([],1,'','PRIVATE-SENTINEL'))
    with pytest.raises(runner.SemgrepInvocationError,match='cleanup'):
        runner.run_semgrep(['main.py'],str(repo),config=str(rules))


def test_malformed_findings_fail_before_filtering(tmp_path,monkeypatch):
    for update in [
        {'check_id':None}, {'path':''}, {'extra':None}, {'start':{'line':0}},
        {'start':{'line':True}}, {'start':{'line':'1'}}, {'end':{'line':0}},
        {'extra':{'severity':'ERROR','message':{'unexpected':'object'}}},
        {'extra':{'severity':'ERROR','message':'risk','metadata':['wrong-shape']}},
        {'extra':{'severity':'CORRUPTED','message':'Risk','metadata':{}}},   # unknown severity must not vanish
    ]:
        with pytest.raises(runner.SemgrepInvocationError,match='finding evidence'):
            scan_output(tmp_path,monkeypatch,finding()|update)
            pytest.fail(f'accepted {update}')


def test_valid_finding_and_intentional_severity_floor_are_preserved(tmp_path,monkeypatch):
    assert len(scan_output(tmp_path,monkeypatch,finding()))==1
    low=finding();low['extra']['severity']='INFO'
    assert scan_output(tmp_path,monkeypatch,low)==[]


def test_auto_removed_container_requires_confirmed_absence(monkeypatch):
    for code,output,expected in [(0,'',True),(1,'',False),(0,'remaining-container-id\n',False)]:
        case=(code,output)
        calls=[]
        def docker(command,**kwargs):
            calls.append(command)
            if command[1]=='rm':return subprocess.CompletedProcess(command,1,'','PRIVATE-SENTINEL')
            assert command[1:4]==['container','ls','-a'],case
            assert 'name=^/prsec-test$' in command,case
            return subprocess.CompletedProcess(command,code,output,'PRIVATE-SENTINEL')
        with monkeypatch.context() as m:
            m.setattr(runner.subprocess,'run',docker)
            if expected:runner._confirm_container_cleanup('prsec-test',{})
            else:
                with pytest.raises(runner.SemgrepInvocationError) as raised:
                    runner._confirm_container_cleanup('prsec-test',{})
                    pytest.fail(f'cleanup confirmed for {case}')
                assert 'PRIVATE-SENTINEL' not in str(raised.value),case
        assert len(calls)==2,case


def test_cleanup_timeout_fails_safely(monkeypatch,caplog):
    def timeout(*args,**kwargs):raise subprocess.TimeoutExpired('docker',15,stderr='PRIVATE-SENTINEL')
    monkeypatch.setattr(runner.subprocess,'run',timeout)
    with pytest.raises(runner.SemgrepInvocationError):runner._confirm_container_cleanup('prsec-test',{})
    assert 'container_cleanup_unconfirmed' in caplog.text
    assert 'PRIVATE-SENTINEL' not in caplog.text


def test_refresh_outage_enters_persistent_retry_not_terminal_failure(tmp_path,monkeypatch):
    import worker
    from job_store import JobStore
    from test_jobs import configure,payload
    configure(monkeypatch);monkeypatch.setattr(app,'JOB_DB',str(tmp_path/'jobs.db'))
    store=JobStore(app.JOB_DB);store.enqueue(payload())
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND','docker')
    monkeypatch.setattr(runner,'verify_docker_sandbox',lambda:None)
    unauthorized=requests.Response();unauthorized.status_code=401
    monkeypatch.setattr(app.requests,'request',lambda *a,**k:unauthorized)
    def refresh(*a):
        response=requests.Response();response.status_code=503
        raise requests.HTTPError('PRIVATE-SENTINEL',response=response)
    monkeypatch.setattr(app,'_get_installation_token',refresh)
    def process(*args):app._gh_request('GET','https://api.github.com/example','fake',install_id=1).raise_for_status()
    monkeypatch.setattr(worker,'process_job',process)
    class Idle(Exception):pass
    def stop(_):raise Idle()
    monkeypatch.setattr(worker.time,'sleep',stop)
    with pytest.raises(Idle):worker.run()
    with store.connect() as db:
        row=db.execute('SELECT state,error,attempts FROM jobs').fetchone()
        assert tuple(row)==('queued','HTTP_503',1)
    assert JobStore(app.JOB_DB).claim() is None
