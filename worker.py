"""Single-host persistent worker. Run separately from the webhook listener."""
import fcntl
import logging
import os
import time
import requests
from pathlib import Path

import app
from job_store import JobStore
from job_payload import pr_job
import re

log = logging.getLogger('worker')


def find_existing_check(payload, key, token):
    owner, repo = payload['base_owner'], payload['base_repo']
    for page in range(1, 11):
        data = app._get_json(
            f"{app.GITHUB_API}/repos/{owner}/{repo}/commits/{payload['head_sha']}/check-runs",
            token, params={'check_name': app.CHECK_NAME, 'filter': 'all', 'per_page': 100, 'page': page},
            install_id=payload['installation_id'])
        checks = data.get('check_runs', [])
        for check in checks:
            if check.get('external_id') == key and str(check.get('app', {}).get('id')) == app.APP_ID:
                return int(check['id'])
        if len(checks) < 100:
            return None
    raise RuntimeError('Check reconciliation pagination exceeded')


def expand_base_push(store, job, token):
    """Read-only GitHub enumeration; atomically replace the event with scan jobs."""
    p = job['payload']; children = []
    for page in range(1, 3):
        rows = app._get_json(f"{app.GITHUB_API}/repos/{p['base_owner']}/{p['base_repo']}/pulls", token,
            params={'state': 'open', 'base': p['base_ref'], 'per_page': 100, 'page': page},
            install_id=p['installation_id'])
        if not isinstance(rows, list): raise ValueError('Malformed PR enumeration')
        for pr in rows:
            if pr.get('state') != 'open': continue
            child = pr_job(pr, pr['number'], p['installation_id'])
            if f"{child['base_owner']}/{child['base_repo']}" != app.ALLOWED_REPOSITORY or child['base_ref'] != p['base_ref']:
                raise ValueError('PR enumeration escaped requested scope')
            children.append(child)
            if len(children) > 100: raise OverflowError('Base push exceeds bounded queue fanout')
        if len(rows) < 100:
            store.expand(job['id'], children)
            return
    raise OverflowError('Base push enumeration exceeded bound')


def process_job(store, job):
    p = job['payload']
    if f"{p['base_owner']}/{p['base_repo']}" != app.ALLOWED_REPOSITORY or p['installation_id'] != app.ALLOWED_INSTALLATION_ID:
        raise RuntimeError('Stored job does not match configured repository')
    if p.get('kind') != 'base_push' and not re.fullmatch(r'[0-9a-f]{40}', p.get('base_sha', '')):
        store.fail(job['id'], 'legacy_base_context_missing')
        log.error('job_terminal_failure job=%s reason=legacy_base_context_missing', job['id'])
        return
    token = app._get_installation_token(p['installation_id'])
    if p.get('kind') == 'base_push':
        expand_base_push(store, job, token)
        return
    check_id = job['check_id'] or find_existing_check(p, job['id'], token)
    if not check_id:
        data = app._post_json(
            f"{app.GITHUB_API}/repos/{p['base_owner']}/{p['base_repo']}/check-runs", token,
            {'name': app.CHECK_NAME, 'head_sha': p['head_sha'], 'status': 'in_progress',
             'external_id': job['id'], 'output': {'title': 'Security scan queued', 'summary': 'Scanning the exact PR commit.'}},
            install_id=p['installation_id'])
        check_id = int(data['id'])
    store.set_check(job['id'], check_id)
    context = {}
    if 'base_sha' in p:
        context = {'expected_base_sha': p['base_sha'], 'expected_base_ref': p.get('base_ref')}
    outcome = app.run_semgrep_pipeline(p['base_owner'], p['base_repo'], p['head_owner'], p['head_repo'],
                            p['pr'], p['head_sha'], p['installation_id'], p['base_owner'],
                            p['base_repo'], check_id, token, **context)
    if isinstance(outcome, dict) and outcome.get('scan_error'):
        reason = 'scan_error:' + outcome['scan_error']
        store.fail(job['id'], reason)
        log.error('job_terminal_failure job=%s reason=%s', job['id'], reason)
    else:
        store.finish(job['id'])


def run():
    if app.MODE != 'durable' or not app.ALLOWED_REPOSITORY or not app.ALLOWED_INSTALLATION_ID:
        raise RuntimeError('Worker requires durable mode and explicit repository/installation scope')
    if os.getenv('PRSEC_SCANNER_BACKEND') != 'docker':
        raise RuntimeError('Durable worker requires the Docker sandbox backend')
    from analyzers.semgrep_runner import verify_docker_sandbox
    verify_docker_sandbox()
    path = Path(app.JOB_DB)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.with_suffix('.worker.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = JobStore(path)
        store.recover()
        while True:
            store.heartbeat()
            job = store.claim()
            if job is None:
                time.sleep(1)
                continue
            try:
                process_job(store, job)
            except Exception as error:
                # No tokens, source data, response bodies, or exception messages in logs.
                log.error('job=%s attempt=%s error_type=%s', job['id'], job['attempts'], type(error).__name__)
                limited = isinstance(error, app.GitHubRateLimitError)
                status = getattr(getattr(error, 'response', None), 'status_code', None)
                reason = f'HTTP_{status}' if isinstance(error, requests.HTTPError) and status else type(error).__name__
                permanent = not limited and (
                    status in app.PERMANENT_HTTP_STATUSES
                    or isinstance(error, (ValueError, TypeError, KeyError, RuntimeError)))
                if permanent:
                    store.fail(job['id'], reason)
                    queued = False
                else:
                    queued = store.retry(job['id'], reason,
                        retry_after=error.retry_after if limited else None)
                if not queued:
                    log.error('job_terminal_failure job=%s reason=%s attempts=%s', job['id'], reason, job['attempts'])


if __name__ == '__main__':
    run()
