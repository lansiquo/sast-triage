"""Real static scans only; no fixture code or payloads are executed."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import demo_web

def test_only_selected_bundled_scenario_reaches_scanner(monkeypatch):
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    for scenario in ['sql', 'command', 'yaml', 'tls']:
        def scan(paths, root, **kwargs):
            assert paths == [demo_web.SCENARIOS[scenario]['fixed'].name]
            assert Path(root) == demo_web.ROOT / 'showcase'
            return []
        monkeypatch.setattr(demo_web, 'run_semgrep', scan)
        assert client.get('/api/fixtures/'+scenario).status_code == 200
        result = client.post('/api/scan/'+scenario+'/fixed', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'})
        assert result.json()['scenario'] == scenario, scenario
        assert result.json()['status'] == 'success', scenario


def test_unknown_scenario_rejected_before_scan(monkeypatch):
    monkeypatch.setattr(demo_web, 'run_semgrep', lambda *a, **k: pytest.fail('must not scan'))
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    assert client.get('/api/fixtures/unknown').status_code == 404
    assert client.post('/api/scan/unknown/fixed', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'}).status_code == 404

def test_bundled_scenarios_live(monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    for scenario in ('sql', 'command', 'yaml', 'tls'):
        for variant in ('vulnerable', 'fixed'):
            case = (scenario, variant)
            response = client.post(f'/api/scan/{scenario}/{variant}', headers={'Origin':'http://127.0.0.1','X-PRSEC-Demo':'1'})
            assert response.status_code == 200, case
            data = response.json()
            assert data['status'] == ('failure' if variant == 'vulnerable' else 'success'), case
            assert len(data['findings']) == (1 if variant == 'vulnerable' else 0), case
