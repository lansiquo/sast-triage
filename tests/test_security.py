import hashlib
import hmac
import io
import os
import json
import subprocess
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
import app
from analyzers import semgrep_runner as runner


def post(body, secret='testsecret', signature=True, event='ping'):
    headers = {'X-GitHub-Event': event, 'X-GitHub-Delivery': 'security-test'}
    if signature:
        headers['X-Hub-Signature-256'] = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return TestClient(app.app).post('/webhook', content=body, headers=headers)


@pytest.mark.parametrize('signature,secret', [(False, 'testsecret'), (True, 'wrong')])
def test_reject_invalid_signature(signature, secret):
    assert post(b'{}', secret, signature).status_code == 401


def test_missing_secret_fails_closed(monkeypatch):
    monkeypatch.setattr(app, 'SECRETS', [])
    assert post(b'{}').status_code == 503


@pytest.mark.parametrize('body', [b'{', b'[]', b'null', b'"text"'])
def test_invalid_json(body):
    assert post(body).status_code == 400


def test_webhook_size_limit(monkeypatch):
    monkeypatch.setattr(app, 'MAX_WEBHOOK_BYTES', 8)
    assert post(b' ' * 9).status_code == 413


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as tf:
        for name, kind, content in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.REGTYPE:
                member.size = len(content)
            elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = '../../outside'
            tf.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    data.seek(0)
    return tarfile.open(fileobj=data)


@pytest.mark.parametrize('name,kind', [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
    ('root/../../sibling/file', tarfile.REGTYPE), ('root/link', tarfile.SYMTYPE),
    ('root/hardlink', tarfile.LNKTYPE), ('root/fifo', tarfile.FIFOTYPE),
    ('root/../sibling/file', tarfile.REGTYPE), ('root\\file', tarfile.REGTYPE)])
def test_unsafe_archive_rejected(tmp_path, name, kind):
    with archive([(name, kind, b'x')]) as tf, pytest.raises(RuntimeError):
        app._safe_extract_tar(tf, tmp_path)


def test_archive_normal_file(tmp_path):
    with archive([('root/main.py', tarfile.REGTYPE, b'print(1)')]) as tf:
        assert app._safe_extract_tar(tf, tmp_path) == 'root'
    assert (tmp_path / 'root/main.py').read_bytes() == b'print(1)'


@pytest.mark.parametrize('limit,value', [('MAX_EXTRACTED_BYTES', 1), ('MAX_ARCHIVE_MEMBERS', 0)])
def test_archive_limits(tmp_path, monkeypatch, limit, value):
    monkeypatch.setattr(app, limit, value)
    with archive([('root/main.py', tarfile.REGTYPE, b'xx')]) as tf, pytest.raises(RuntimeError):
        app._safe_extract_tar(tf, tmp_path)


def test_duplicate_archive_path(tmp_path):
    with archive([('root/a', tarfile.REGTYPE, b'a')] * 2) as tf, pytest.raises(RuntimeError):
        app._safe_extract_tar(tf, tmp_path)


def test_pipeline_failure_is_not_success(monkeypatch, tmp_path):
    (tmp_path / 'main.py').write_text('print(1)')
    monkeypatch.setattr(app, 'download_tarball', lambda *args: tmp_path)
    monkeypatch.setattr(app, 'list_changed_files', lambda *args: {'main.py': None})
    def fail(**kwargs):
        raise RuntimeError('scan failed')
    monkeypatch.setattr(app, 'run_semgrep', fail)
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *args: completed.append(args))
    app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 1, 'fake')
    assert completed[0][3] == 'failure'
    assert 'incomplete' in completed[0][5]


@pytest.mark.parametrize('result', [subprocess.CompletedProcess([], -9, '{}', ''),
    subprocess.CompletedProcess([], 2, '{}', ''), subprocess.CompletedProcess([], 0, 'not-json', ''),
    subprocess.CompletedProcess([], 0, '{"results": [], "errors": [{"message": "parse error"}]}', '')])
def test_scanner_failure(tmp_path, monkeypatch, result):
    (tmp_path / 'main.py').write_text('print(1)')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    monkeypatch.setattr(runner, '_bounded_container_run', lambda *a, **k: result)
    with pytest.raises(runner.SemgrepInvocationError):
        runner.run_semgrep(['main.py'], str(tmp_path), config='/trusted/rules.yml')


@pytest.mark.parametrize('path', ['../outside.py', '/tmp/outside.py'])
def test_scan_path_boundary(tmp_path, monkeypatch, path):
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    with pytest.raises(ValueError):
        runner.run_semgrep([path], str(tmp_path), config='/trusted/rules.yml')

@pytest.mark.parametrize('owner,sha', [('owner/../../other', 'a' * 40), ('owner', 'not-a-sha')])
def test_invalid_pr_identifiers(owner, sha):
    side = {'sha': sha, 'repo': {'owner': {'login': owner}, 'name': 'repo'}}
    payload = {'action': 'opened', 'number': 1, 'pull_request': {'head': side, 'base': side}}
    assert post(json.dumps(payload).encode(), event='pull_request').status_code == 400


def test_rotated_secret(monkeypatch):
    monkeypatch.setattr(app, 'SECRETS', ['old', 'new'])
    assert post(b'{}', secret='new').json() == {'ok': True, 'pong': True}


def test_download_limit_closes_response(tmp_path, monkeypatch):
    class Response:
        status_code = 200
        closed = False
        def raise_for_status(self): pass
        def iter_content(self, chunk_size): yield b'x' * 11
        def close(self): self.closed = True
    response = Response()
    monkeypatch.setattr(app, 'MAX_ARCHIVE_BYTES', 10)
    monkeypatch.setattr(app, '_gh_request', lambda *a, **k: response)
    with pytest.raises(RuntimeError, match='size limit'):
        app.download_tarball('o', 'r', 'a' * 40, 'fake', 1, tmp_path)
    assert response.closed


def test_annotations_batched(monkeypatch):
    batches = []
    monkeypatch.setattr(app, '_patch_json', lambda url, token, payload, **k: batches.append(payload))
    app.complete_check_run('o', 'r', 1, 'failure', 'title', 'summary', [{}] * 123, 'fake', 1)
    assert [len(b['output']['annotations']) for b in batches] == [50, 50, 23]


def test_reserved_slot_released_on_error(monkeypatch):
    import threading
    gate = threading.BoundedSemaphore(1)
    gate.acquire()
    monkeypatch.setattr(app, 'SCAN_SLOTS', gate)
    def fail(*args): raise RuntimeError('failed')
    monkeypatch.setattr(app, 'run_semgrep_pipeline', fail)
    with pytest.raises(RuntimeError): app._run_reserved_scan()
    assert gate.acquire(blocking=False)


def test_semgrep_skips_stale_virtualenv_launcher(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'semgrep')
    local = tmp_path / "venv" / "bin"
    installed = tmp_path / "installed" / "bin"
    local.mkdir(parents=True)
    installed.mkdir(parents=True)
    stale = local / "semgrep"
    stale.write_text("#!/missing/old-venv/python\n")
    stale.chmod(0o755)
    working = installed / "semgrep"
    working.write_text("#!/bin/sh\nexit 0\n")
    working.chmod(0o755)
    monkeypatch.setattr(runner.sys, "executable", str(local / "python"))
    monkeypatch.setenv("PATH", os.pathsep.join([str(local), str(installed)]))
    monkeypatch.delenv("SEMGREP_BIN", raising=False)
    assert runner._ensure_semgrep_available() == str(working)
    monkeypatch.setenv("SEMGREP_BIN", str(stale))
    with pytest.raises(runner.SemgrepInvocationError, match="No usable"):
        runner._ensure_semgrep_available()


def test_semgrep_prefers_matching_python_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_SCANNER_COMMAND', 'semgrep')
    executable = tmp_path / "semgrep"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.delenv("SEMGREP_BIN", raising=False)
    assert runner._ensure_semgrep_available() == str(executable)


def test_skipped_source_cannot_pass(tmp_path, monkeypatch):
    (tmp_path / 'main.py').write_text('print(1)')
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    monkeypatch.setattr(runner, '_bounded_container_run', lambda *a, **k:
        subprocess.CompletedProcess([], 0, '{"results": [], "errors": [], "paths": {"scanned": []}}', ''))
    with pytest.raises(runner.SemgrepInvocationError, match='skipped'):
        runner.run_semgrep(['main.py'], str(tmp_path), config='/trusted/rules.yml')


def test_oversized_source_rejected_before_scanner(tmp_path, monkeypatch):
    (tmp_path / 'large.py').write_bytes(b'x' * (1024 * 1024 + 1))
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    with pytest.raises(ValueError, match='1 MiB'):
        runner.run_semgrep(['large.py'], str(tmp_path), config='/trusted/rules.yml')


def test_scanner_cannot_access_outside_symlink(tmp_path, monkeypatch):
    outside=tmp_path / 'private.txt';outside.write_text('test-only-private-data')
    root=tmp_path / 'repo';root.mkdir();(root / 'source.py').symlink_to(outside)
    monkeypatch.setattr(runner, '_ensure_semgrep_available', lambda: '/fake/semgrep')
    with pytest.raises(ValueError, match='Unsafe scan path'):
        runner.run_semgrep(['source.py'], str(root), config='/trusted/rules.yml')


def test_real_scanner_process_gets_only_staged_source_and_safe_environment(tmp_path, monkeypatch):
    import sys
    repo=tmp_path / 'repo';repo.mkdir()
    (repo/'main.py').write_text('print(1)')
    (repo/'.env').write_text('TEST_ONLY_SECRET=not-for-child')
    (repo/'.semgrepignore').write_text('*')
    (repo/'.semgrep.yaml').write_text('untrusted configuration')
    executable=tmp_path/'fake-scanner'
    executable.write_text('#!'+sys.executable+'\n'+'''
import json, os
from pathlib import Path
assert 'PRSEC_TEST_ONLY_SECRET' not in os.environ
for name in ('GITHUB_APP_PRIVATE_KEY', 'GITHUB_APP_PRIVATE_KEY_PATH',
             'GITHUB_WEBHOOK_SECRET', 'GITHUB_WEBHOOK_SECRETS',
             'EXPLICIT_INSTALLATION_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'SEMGREP_APP_TOKEN'):
    assert name not in os.environ
assert not Path('.env').exists()
assert not Path('.semgrepignore').exists()
assert not Path('.semgrep.yaml').exists()
assert Path('main.py').read_text() == 'print(1)'
assert Path(os.environ['HOME']).resolve() == Path.cwd()
print(json.dumps({'results': [], 'errors': [], 'paths': {'scanned': ['main.py']}}))
''')
    executable.chmod(0o755)
    monkeypatch.setenv('PRSEC_TEST_ONLY_SECRET','not-for-child')
    for name in ('GITHUB_APP_PRIVATE_KEY', 'GITHUB_APP_PRIVATE_KEY_PATH',
                 'GITHUB_WEBHOOK_SECRET', 'GITHUB_WEBHOOK_SECRETS',
                 'EXPLICIT_INSTALLATION_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'SEMGREP_APP_TOKEN'):
        monkeypatch.setenv(name, 'TEST-ONLY-SENTINEL')
    monkeypatch.setenv('SEMGREP_BIN',str(executable))
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND','local')
    assert runner.run_semgrep(['main.py'], str(repo), config='/trusted/rules.yml') == []


def test_durable_mode_refuses_unsandboxed_scanner(monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'durable')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    with pytest.raises(RuntimeError, match='unsandboxed'):
        runner.run_semgrep(['main.py'], '/unused', config='/trusted/rules.yml')


def test_docker_controller_and_container_do_not_receive_app_secrets(tmp_path, monkeypatch):
    (tmp_path/'main.py').write_text('print(1)')
    rules=tmp_path/'trusted.yml';rules.write_text('rules: []')
    monkeypatch.setenv('PRSEC_MODE','durable')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND','docker')
    monkeypatch.setenv('PRSEC_SCANNER_IMAGE','example/scanner@sha256:'+'a'*64)
    secret_names=('GITHUB_APP_PRIVATE_KEY','GITHUB_APP_PRIVATE_KEY_PATH',
                  'GITHUB_WEBHOOK_SECRET','GITHUB_WEBHOOK_SECRETS',
                  'EXPLICIT_INSTALLATION_TOKEN','GITHUB_TOKEN','GH_TOKEN','SEMGREP_APP_TOKEN')
    for name in secret_names: monkeypatch.setenv(name,'TEST-ONLY-SENTINEL')
    def controller(cmd, cwd, env, timeout):
        assert not set(secret_names) & set(env)
        assert not any('TEST-ONLY-SENTINEL' in arg for arg in cmd)
        mounts=[cmd[index+1] for index,arg in enumerate(cmd) if arg=='--mount']
        assert len(mounts)==2
        assert all(mount.endswith(',readonly') for mount in mounts)
        assert {mount.split('target=')[1].split(',')[0] for mount in mounts}=={'/scan','/rules.yaml'}
        assert all(not any(name in arg for name in secret_names) for arg in cmd if arg.startswith('--env'))
        return subprocess.CompletedProcess(cmd,0,'{"results":[],"errors":[],"paths":{"scanned":["main.py"]}}','')
    monkeypatch.setattr(runner,'_bounded_container_run',controller)
    def cleanup(cmd, **kwargs):
        assert not set(secret_names) & set(kwargs['env'])
        return subprocess.CompletedProcess(cmd,0,'','')
    monkeypatch.setattr(runner.subprocess,'run',cleanup)
    assert runner.run_semgrep(['main.py'],str(tmp_path),config=str(rules))==[]
