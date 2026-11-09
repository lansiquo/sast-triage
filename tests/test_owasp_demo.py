"""Static examples are scanned; authored behavioral fixtures run only in the bounded lab."""
import ast
import pytest
from fastapi.testclient import TestClient
import demo_web

HEADERS = {'Origin': 'http://127.0.0.1', 'X-PRSEC-Demo': '1'}


def test_catalog_has_exact_2025_categories_and_real_fixtures():
    assert len(demo_web.CATALOG) == 10
    assert [v['category'][:3] for v in demo_web.CATALOG.values()] == [f'A{i:02}' for i in range(1, 11)]
    for key, meta in demo_web.CATALOG.items():
        assert meta['source'].startswith('https://top10.owasp.org/2025/')
        for path in demo_web.SCENARIOS[key].values():
            ast.parse(path.read_text())  # Parse only: no import/exec.


BEHAVIORAL = [k for k, v in demo_web.CATALOG.items() if v['mode'] == 'behavioral']


def test_behavioral_examples_execute_and_return_assertions(monkeypatch):
    assert BEHAVIORAL
    monkeypatch.setattr(demo_web, 'run_semgrep', lambda *a, **k: pytest.fail('Behavioral examples must not call scanner'))
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    for scenario in BEHAVIORAL:
        for variant in ('vulnerable', 'fixed'):
            case = (scenario, variant)
            response = client.post(f'/api/scan/{scenario}/{variant}', headers=HEADERS)
            assert response.status_code == 200, case
            result = response.json()
            assert result['status'] == ('failure' if variant == 'vulnerable' else 'success'), case
            assert result['engine'] == 'behavioral', case
            assert result['harness_completed'] is True, case
            assert result['assertions'], case
            assert all(a['passed'] for a in result['assertions']) == (variant == 'fixed'), case
            assert result['findings'] == [], case
            assert 'synthetic' in result['provenance'], case
            data = client.get(f'/api/fixtures/{scenario}').json()
            assert data['source'][variant], case
            assert '+ ' in data['diff'] or '+' in data['diff'], case


def test_config_fixture_live(monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    for variant in ('vulnerable', 'fixed'):
        result = client.post(f'/api/scan/config/{variant}', headers=HEADERS).json()
        assert result['status'] == ('failure' if variant == 'vulnerable' else 'success'), variant
        assert {f['rule_id'] for f in result['findings']} == (
            {'demo-python-fastapi-debug'} if variant == 'vulnerable' else set()), variant


def test_highlights_target_existing_specific_code_lines():
    client = TestClient(demo_web.app, base_url='http://127.0.0.1')
    for scenario in demo_web.CATALOG:
        data = client.get(f'/api/fixtures/{scenario}').json()
        assert data['review_mode'] == demo_web.CATALOG[scenario]['mode'], scenario
        for variant in ('vulnerable', 'fixed'):
            case = (scenario, variant)
            lines = data['source'][variant].splitlines()
            focus = data['highlights'][variant]
            assert focus and len(set(focus)) == len(focus), case
            assert len(focus) < len(lines), case
            for number in focus:
                assert 1 <= number <= len(lines), (case, number)
                assert lines[number-1].strip() and not lines[number-1].lstrip().startswith('#'), (case, number)
