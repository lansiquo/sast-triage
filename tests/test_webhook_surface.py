"""The webhook app publishes no API docs and reads .env only when asked to."""
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

import app

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize('path', ['/docs', '/redoc', '/openapi.json', '/docs/oauth2-redirect'])
def test_webhook_app_publishes_no_schema_or_docs_ui(path):
    assert TestClient(app.app).get(path).status_code == 404


def secret_seen_by_fresh_import(tmp_path, **env):
    """Import app in a clean process whose working directory holds a .env."""
    (tmp_path / '.env').write_text('GITHUB_WEBHOOK_SECRET=from-dotenv\n')
    child_env = {key: os.environ[key] for key in ('PATH', 'LANG', 'SYSTEMROOT') if key in os.environ}
    child_env.update(PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', **env)
    result = subprocess.run([sys.executable, '-c', 'import app; print(app.WEBHOOK_SECRET)'],
                            cwd=tmp_path, env=child_env, capture_output=True, text=True, timeout=60, check=True)
    return result.stdout.strip()


def test_dotenv_in_working_directory_is_ignored_by_default(tmp_path):
    assert secret_seen_by_fresh_import(tmp_path) == ''


def test_dotenv_is_loaded_when_explicitly_enabled(tmp_path):
    assert secret_seen_by_fresh_import(tmp_path, PRSEC_LOAD_DOTENV='1') == 'from-dotenv'


def test_make_serve_enables_dotenv_for_the_documented_local_flow():
    serve = (REPO / 'Makefile').read_text().split('serve:', 1)[1].splitlines()[1]
    assert serve.strip().startswith('PRSEC_LOAD_DOTENV=1 ') and 'uvicorn app:app' in serve
