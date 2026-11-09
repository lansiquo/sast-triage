from fastapi.testclient import TestClient
import pytest
import demo_web

HEADERS = {'Origin': 'http://127.0.0.1', 'X-PRSEC-Demo': '1'}

@pytest.fixture
def client():
    return TestClient(demo_web.app, base_url='http://127.0.0.1')


def test_demo_serves_only_fixed_assets_and_fixtures(client):
    page = client.get('/')
    assert page.status_code == 200
    assert "frame-ancestors 'none'" in page.headers['content-security-policy']
    assert client.get('/ui/demo.js').status_code == 200
    assert client.get('/ui/.env').status_code == 404
    assert client.get('/api/fixtures').json()['source'].keys() == {'vulnerable', 'fixed'}
    assert client.get('/api/fixtures', headers={'Host': 'evil.example'}).status_code == 400


def test_cross_site_scan_rejected(client, monkeypatch):
    monkeypatch.setattr(demo_web, 'run_semgrep', lambda *a, **k: pytest.fail('Scanner must not run'))
    for headers in [{}, {'Origin': 'http://evil.example', 'X-PRSEC-Demo': '1'}, {'Origin': 'http://127.0.0.1'}]:
        assert client.post('/api/scan/vulnerable', headers=headers).status_code == 403, headers


def test_demo_restricts_inputs_and_passes_only_trusted_rules(client, monkeypatch):
    def scan(paths, root, config, timeout_s):
        from pathlib import Path
        assert paths == ['fixed.py']
        assert Path(root) == demo_web.ROOT / 'showcase'
        assert Path(config).read_text() == demo_web.OFFLINE_RULESET
        assert timeout_s == 30
        return []
    monkeypatch.setattr(demo_web, 'run_semgrep', scan)
    assert client.post('/api/scan/other', headers=HEADERS).status_code == 404
    result = client.post('/api/scan/fixed', headers=HEADERS).json()
    assert result['status'] == 'success'
    assert 'Live local' in result['provenance']


def test_demo_error_is_sanitized_and_releases_lock(client, monkeypatch):
    def fail(*a, **k):
        raise RuntimeError('TEST-SECRET-DO-NOT-DISCLOSE')
    monkeypatch.setattr(demo_web, 'run_semgrep', fail)
    response = client.post('/api/scan/fixed', headers=HEADERS)
    assert response.status_code == 503 and response.json()['status'] == 'error'
    assert 'TEST-SECRET' not in response.text
    assert demo_web.SCAN_LOCK.acquire(blocking=False)
    try:
        assert client.post('/api/scan/fixed', headers=HEADERS).status_code == 429
    finally:
        demo_web.SCAN_LOCK.release()
