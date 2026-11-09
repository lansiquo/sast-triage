from __future__ import annotations

"""Authenticated GitHub PR webhooks with bounded, trusted-rule Semgrep scans."""

import io
import math
from email.utils import parsedate_to_datetime
import re
import shutil
import threading
import json
import logging
import os
import time
import hmac
import tarfile
import hashlib
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set, Tuple

import certifi
import requests
from fastapi import BackgroundTasks, FastAPI, Header, Request, HTTPException
from dotenv import load_dotenv

# Opt-in only (`make serve` sets PRSEC_LOAD_DOTENV=1): a service must not
# pick up whatever .env happens to sit in its working directory.
if os.getenv("PRSEC_LOAD_DOTENV", "0") == "1":
    load_dotenv(dotenv_path=".env")

# Ensure we see everything unless caller overrides
os.environ.setdefault("PRSEC_SEMGREP_MIN_SEVERITY", "LOW")
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

# --- analyzers (our runner) ---
from analyzers.semgrep_runner import run_semgrep, to_github_annotations, summarize_findings
from analyzers.triage import changed_lines, gate, is_source_path, triage

# PyJWT optional
try:
    import jwt  # type: ignore
except Exception:  # pragma: no cover
    jwt = None

# ---------------- App / Logging ----------------
# A webhook receiver has no human API consumers; publish no schema or docs UI.
app = FastAPI(title="PRSec Webhook", version="3.4.0", docs_url=None, redoc_url=None, openapi_url=None)
log = logging.getLogger("webhook")
logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"))
BOOT_TS = time.time()

# ---------------- Config ----------------
GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com").rstrip("/")

# Required webhook secrets; comma-separated values support rotation.
WEBHOOK_SECRET = (os.getenv("GITHUB_WEBHOOK_SECRET") or "").strip()
SECRETS = [s.strip() for s in (os.getenv("GITHUB_WEBHOOK_SECRETS") or WEBHOOK_SECRET).split(",") if s.strip()]
# Authentication cannot be disabled by a stale development environment.
MAX_WEBHOOK_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
SCAN_SLOTS = threading.BoundedSemaphore(2)
MODE = os.getenv("PRSEC_MODE", "local")
ALLOWED_REPOSITORY = os.getenv("PRSEC_ALLOWED_REPOSITORY", "")
ALLOWED_INSTALLATION_ID = int(os.getenv("PRSEC_ALLOWED_INSTALLATION_ID", "0"))
JOB_DB = os.getenv("PRSEC_JOB_DB", "data/jobs.sqlite3")

# GitHub App creds
APP_ID = (os.getenv("GITHUB_APP_ID") or "").strip()
APP_PEM_PATH = (os.getenv("GITHUB_APP_PRIVATE_KEY_PATH") or "").strip()
APP_PEM_INLINE = (os.getenv("GITHUB_APP_PRIVATE_KEY") or "").strip()

# Token fallback/debug
EXPLICIT_INSTALLATION_TOKEN = (os.getenv("EXPLICIT_INSTALLATION_TOKEN") or "").strip()
FORCE_EXPLICIT_TOKEN = os.getenv("FORCE_EXPLICIT_TOKEN") == "1"

# Timeouts / limits
HTTP_TIMEOUT_S      = int(os.getenv("HTTP_TIMEOUT_S", "25"))
SEMGREP_TIMEOUT_S   = int(os.getenv("SEMGREP_TIMEOUT_S", "120"))

# Scan/reporting
CHECK_NAME      = os.getenv("PRSEC_CHECK_NAME", "PRSecurityScan")
SEMGREP_EXCLUDE = [s for s in (os.getenv("SEMGREP_EXCLUDE") or "").split(",") if s]
MAX_ANNOTS      = int(os.getenv("PRSEC_MAX_ANNOTATIONS", "200"))

# GitHub responses a retry cannot fix (rate limits are handled separately).
PERMANENT_HTTP_STATUSES = frozenset({400, 401, 403, 404, 405, 410, 422})

# ---------- Helpers ----------
def _hmac_sig(secret: str, body: bytes, algo: str) -> str:
    h = {"sha256": hashlib.sha256, "sha1": hashlib.sha1}[algo.lower()]
    return f"{algo.lower()}=" + hmac.new(secret.encode("utf-8"), body, h).hexdigest()

def _bearer(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "prsec-webhook/1.0",
    }

def _ca_bundle() -> str:
    return os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE") or certifi.where()

def _read_private_key() -> str:
    key = Path(APP_PEM_PATH).read_text() if APP_PEM_PATH else APP_PEM_INLINE.replace("\\n", "\n").strip()
    if not key.startswith("-----BEGIN") or "PRIVATE KEY" not in key:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY[_PATH] is not a valid PEM private key")
    return key

def _create_app_jwt() -> str:
    if not APP_ID:
        raise RuntimeError("GITHUB_APP_ID is missing")
    if jwt is None:
        raise RuntimeError("PyJWT not installed; pip install PyJWT")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": APP_ID}
    token = jwt.encode(payload, _read_private_key(), algorithm="RS256")
    return token.decode() if isinstance(token, (bytes, bytearray)) else token

class GitHubRateLimitError(requests.HTTPError):
    """Safe error carrying a server-directed delay, never response text."""
    def __init__(self, response, retry_after):
        super().__init__('GitHub rate limit; retry deferred', response=response)
        self.retry_after = retry_after


def _raise_for_rate_limit(response):
    if response.status_code not in (403, 429):
        return
    headers = response.headers
    if response.status_code != 429 and not (response.status_code == 403 and
            ('Retry-After' in headers or headers.get('X-RateLimit-Remaining') == '0')):
        return
    delays = [60.0]
    if headers.get('Retry-After'):
        value = headers['Retry-After']
        try:
            delay = float(value)
        except ValueError:
            try:
                delay = parsedate_to_datetime(value).timestamp() - time.time()
            except (ValueError, TypeError, OverflowError):
                delay = 60.0
        if math.isfinite(delay):
            delays.append(max(0.0, delay))
    if headers.get('X-RateLimit-Remaining') == '0':
        try:
            delay = float(headers['X-RateLimit-Reset']) - time.time()
            if math.isfinite(delay):
                delays.append(max(0.0, delay))
        except (KeyError, ValueError):
            pass
    raise GitHubRateLimitError(response, max(delays))


def _gh_request(method: str, url: str, token: str, install_id: Optional[int] = None, **kwargs) -> requests.Response:
    r = requests.request(method, url, headers=_bearer(token), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
    if r.status_code == 401 and install_id:
        try:
            fresh = _get_installation_token(int(install_id))
            r = requests.request(method, url, headers=_bearer(fresh), timeout=HTTP_TIMEOUT_S, verify=_ca_bundle(), **kwargs)
        except Exception as e:
            log.error("401 retry failed error_type=%s", type(e).__name__)
            if isinstance(e, requests.RequestException):
                # Preserve the refresh failure: a transient 5xx/connection error
                # must reach worker retry policy instead of becoming the old 401.
                raise
    _raise_for_rate_limit(r)
    return r

def _post_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    r = _gh_request("POST", url, token, install_id=install_id, json=payload)
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("GitHub POST failed status=%s", r.status_code)
    else:
        loc = (try_json or {}).get("html_url") or r.headers.get("Location")
        if loc:
            log.info("POST %s -> %s Created: %s", url, r.status_code, loc)
    r.raise_for_status()
    return try_json or {}

def _patch_json(url: str, token: str, payload: dict, install_id: Optional[int] = None) -> dict:
    r = _gh_request("PATCH", url, token, install_id=install_id, json=payload)
    try:
        try_json = r.json()
    except Exception:
        try_json = None
    if r.status_code >= 400:
        log.error("GitHub PATCH failed status=%s", r.status_code)
    r.raise_for_status()
    return try_json or {}

def _get_json(url: str, token: str, params: Optional[dict] = None, install_id: Optional[int] = None) -> dict:
    r = _gh_request("GET", url, token, install_id=install_id, params=params or {})
    if r.status_code >= 400:
        log.error("GitHub GET failed status=%s", r.status_code)
    r.raise_for_status()
    return r.json()

def _get_installation_token(installation_id: int) -> str:
    if MODE == "durable" and (installation_id != ALLOWED_INSTALLATION_ID or not ALLOWED_REPOSITORY):
        raise RuntimeError("Installation is outside configured scope")
    if installation_id and (MODE == "durable" or not FORCE_EXPLICIT_TOKEN):
        app_jwt = _create_app_jwt()
        url = f"{GITHUB_API}/app/installations/{installation_id}/access_tokens"
        scope = {}
        if ALLOWED_REPOSITORY:
            scope = {"repositories": [ALLOWED_REPOSITORY.split("/")[1]],
                     "permissions": {"contents": "read", "pull_requests": "read", "checks": "write"}}
        r = requests.post(url, headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
                          json=scope, timeout=HTTP_TIMEOUT_S, verify=_ca_bundle())
        if r.status_code >= 400:
            log.error("GitHub token request failed status=%s", r.status_code)
        _raise_for_rate_limit(r)
        r.raise_for_status()
        return r.json()["token"]
    if EXPLICIT_INSTALLATION_TOKEN:
        return EXPLICIT_INSTALLATION_TOKEN
    raise RuntimeError("No installation token available")

# ---------- Safe tar extraction (member-by-member) ----------
def _safe_extract_tar(tf: tarfile.TarFile, dest_dir: Path) -> str:
    base = dest_dir.resolve()
    total = 0
    root_name = None
    seen = set()
    for index, member in enumerate(tf):
        if index >= MAX_ARCHIVE_MEMBERS:
            raise RuntimeError("Archive has too many members")
        name = PurePosixPath(member.name)
        if (name.is_absolute() or ".." in name.parts or not name.parts
                or "\\" in member.name or not (member.isdir() or member.isreg())):
            raise RuntimeError("Unsafe archive member")
        if root_name is None:
            root_name = name.parts[0]
        if name.parts[0] != root_name or (len(name.parts) == 1 and not member.isdir()):
            raise RuntimeError("Archive must have one root directory")
        target = base.joinpath(*name.parts)
        if not target.resolve().is_relative_to(base) or target in seen:
            raise RuntimeError("Unsafe or duplicate archive path")
        seen.add(target)
        total += member.size
        if member.size < 0 or total > MAX_EXTRACTED_BYTES:
            raise RuntimeError("Archive exceeds extraction size limit")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError("Unreadable archive member")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
    if not root_name:
        raise RuntimeError("Empty archive")
    return root_name


# ---------- GitHub Checks helpers ----------
def _create_check_in_progress(owner: str, repo: str, head_sha: str, name: str, title: str, summary: str, token: str, install_id: Optional[int]) -> int:
    data = {"name": name, "head_sha": head_sha, "status": "in_progress", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "output": {"title": title, "summary": summary}}
    resp = _post_json(f"{GITHUB_API}/repos/{owner}/{repo}/check-runs", token, data, install_id=install_id)
    return int(resp.get("id") or 0)

def create_check_in_progress_with_fallback(base_owner: str, base_repo: str, head_owner: str, head_repo: str, head_sha: str, name: str, title: str, summary: str, token: str, install_id: Optional[int]) -> Tuple[str, str, int]:
    try:
        check_id = _create_check_in_progress(base_owner, base_repo, head_sha, name, title, summary, token, install_id)
        return base_owner, base_repo, check_id
    except requests.HTTPError as e:
        rc = getattr(e.response, "status_code", 0)
        if rc in (403, 404, 422):
            log.info("check-run create fallback to head repo due to %s", rc)
            check_id = _create_check_in_progress(head_owner, head_repo, head_sha, name, title, summary, token, install_id)
            return head_owner, head_repo, check_id
        raise

def complete_check_run(owner: str, repo: str, check_id: int, conclusion: str, title: str, summary: str, annotations: List[Dict[str, Any]], token: str, install_id: Optional[int]) -> None:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/check-runs/{check_id}"
    payload = {"status": "completed", "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "conclusion": conclusion, "output": {"title": title, "summary": summary, "annotations": annotations[:50]}}
    _patch_json(url, token, payload, install_id=install_id)
    rest = annotations[50:]
    while rest:
        batch, rest = rest[:50], rest[50:]
        _patch_json(url, token, {"output": {"title": title, "summary": summary, "annotations": batch}}, install_id=install_id)

# ---------- Repo utilities ----------
def list_changed_files(owner: str, repo: str, pr: int, token: str, install_id: Optional[int]) -> Dict[str, Optional[Set[int]]]:
    """Map each changed, non-deleted file to the lines the PR added or changed (None = unknown)."""
    files: Dict[str, Optional[Set[int]]] = {}
    page = 1
    while page <= 30:
        js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files", token, params={"per_page": 100, "page": page}, install_id=install_id)
        if not isinstance(js, list) or any(not isinstance(x, dict) or not isinstance(x.get('filename'), str) for x in js):
            raise RuntimeError('Invalid PR file list')
        if not js:
            break
        files.update((x['filename'], changed_lines(x)) for x in js if x.get('status') != 'removed')
        if len(js) < 100:
            break
        page += 1
    else:
        raise RuntimeError("PR file list exceeded supported pagination limit")
    return files

def download_tarball(owner: str, repo: str, sha: str, token: str, install_id: Optional[int], workdir: Path) -> Path:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
    r = _gh_request("GET", url, token, install_id=install_id, stream=True)
    if r.status_code >= 400:
        log.error("GitHub GET failed status=%s", r.status_code)
    r.raise_for_status()
    tar_bytes = io.BytesIO()
    started = time.monotonic()
    try:
        for chunk in r.iter_content(chunk_size=65536):
            if time.monotonic() - started > 60:
                raise RuntimeError("Archive download deadline exceeded")
            if tar_bytes.tell() + len(chunk) > MAX_ARCHIVE_BYTES:
                raise RuntimeError("Archive download exceeds size limit")
            tar_bytes.write(chunk)
    finally:
        r.close()
    tar_bytes.seek(0)
    with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tf:
        root_name = _safe_extract_tar(tf, workdir)
    repo_root = workdir / (root_name or "")
    if not repo_root.exists():
        # fallback: choose the first extracted dir
        subs = [p for p in workdir.iterdir() if p.is_dir()]
        if not subs:
            raise RuntimeError("Failed to locate repo root in tarball")
        repo_root = subs[0]
    return repo_root

# ---------- Scanning pipeline ----------
def run_semgrep_pipeline(
    base_owner: str,
    base_repo: str,
    head_owner: str,
    head_repo: str,
    pr: int,
    head_sha: str,
    installation_id: int,
    check_owner: str,
    check_repo: str,
    check_id: int,
    token: str,
    expected_base_sha: Optional[str] = None,
    expected_base_ref: Optional[str] = None,
) -> Optional[dict]:
    conclusion = "failure"
    title = f"{CHECK_NAME} results"
    summary = "Scan failed."
    annotations: List[Dict[str, Any]] = []
    scan_error = None

    def _stale(current):
        return (current.get('state') == 'closed' or current.get('head', {}).get('sha') != head_sha
                or (expected_base_sha is not None and current.get('base', {}).get('sha') != expected_base_sha)
                or (expected_base_ref is not None and current.get('base', {}).get('ref') != expected_base_ref))

    def _safe_complete():
        try:
            try_ann = annotations[:MAX_ANNOTS] if annotations else []
            try:
                complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, try_ann, token, installation_id)
            except requests.HTTPError as e:
                if getattr(e.response, "status_code", 0) == 422:
                    complete_check_run(check_owner, check_repo, check_id, conclusion, title, summary, [], token, installation_id)
                else:
                    raise
        except Exception as e:
            log.error("final completion failed type=%s", type(e).__name__)
            if MODE == "durable":
                raise

    defer_completion = False
    try:
        with tempfile.TemporaryDirectory(prefix="prsec_") as td:
            tdp = Path(td)

            if MODE == "durable":
                current = _get_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/pulls/{pr}",
                                    token, install_id=installation_id)
                if _stale(current):
                    conclusion = "cancelled"
                    summary = "PR closed or superseded by a newer commit; this job was not scanned."
                    return
            # 1) Download repo snapshot at PR HEAD. GitHub keeps every PR head
            # commit in the base repository (refs/pull/N/head), so fork PRs are
            # read with the base-scoped installation token too.
            repo_root = download_tarball(base_owner, base_repo, head_sha, token, installation_id, tdp)

            # Scan the immutable snapshot with service-owned rules only.
            # Repository rules/ignore files are untrusted and never configure this scan.
            changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            if MODE == "durable":
                current = _get_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/pulls/{pr}",
                                    token, install_id=installation_id)
                if _stale(current):
                    conclusion = "cancelled"
                    summary = "PR closed or changed during preparation; this job was not scanned."
                    return
            for name in changed:
                candidate = repo_root / name
                if Path(name).is_absolute() or not candidate.resolve().is_relative_to(repo_root.resolve()):
                    raise RuntimeError("Unsafe changed-file path")
            existing = [p for p in changed if is_source_path(p)]
            if any(not (repo_root / p).is_file() for p in existing):
                raise RuntimeError('Changed source file is missing from the commit snapshot')
            if not existing:
                conclusion = "neutral"
                summary = ("No supported changed Python, JavaScript or TypeScript files to scan "
                           "(deleted files are excluded).")
                return
            offline_yaml = tdp / "trusted-rules.yaml"
            offline_yaml.write_text(OFFLINE_RULESET)
            cfg_value = str(offline_yaml)

            # beefier excludes
            ex = [e for e in SEMGREP_EXCLUDE] if SEMGREP_EXCLUDE else []
            for e in (".venv", "venv", ".git", "__pycache__", "**/*.pyc", "**/*.pyo", "**/*.class"):
                if e not in ex:
                    ex.append(e)

            log.info("SEMGREP_CONFIGS=%s EXCLUDE=%s", cfg_value, ex)
            log.info("Scan root=%s file_count=%d sample=%s", repo_root, len(existing), existing[:10])

            # 4) Run Semgrep
            findings = run_semgrep(
                paths=existing, repo_root=str(repo_root), config=cfg_value,
                exclude=ex, timeout_s=SEMGREP_TIMEOUT_S,
            )

            # A PR can close or advance while Semgrep is running.
            if MODE == 'durable':
                current = _get_json(f'{GITHUB_API}/repos/{base_owner}/{base_repo}/pulls/{pr}',
                                    token, install_id=installation_id)
                if _stale(current):
                    conclusion = 'cancelled'
                    summary = 'PR closed or changed during scanning; this result is stale.'
                    return

            # 5) Triage, summarize & annotate (sorted P1 first, so the cap never drops a P1 for a P3)
            findings = triage(findings, changed)
            counts, summary_md = summarize_findings(findings)
            annotations = to_github_annotations(findings)[:MAX_ANNOTS]

            # Only new P1 findings fail the check; everything else stays annotated.
            conclusion = gate(findings)
            new_p1 = counts["P1"]["new"]
            title = f"{new_p1} new P1 finding" + ("" if new_p1 == 1 else "s")
            summary = summary_md

    except GitHubRateLimitError:
        defer_completion = True
        raise
    except Exception as e:
        status = getattr(getattr(e, 'response', None), 'status_code', None)
        permanent = isinstance(e, requests.HTTPError) and status in PERMANENT_HTTP_STATUSES
        if MODE == 'durable' and isinstance(e, requests.RequestException) and not permanent:
            # Transient: the worker retries and completes this Check later.
            defer_completion = True
            raise
        if permanent:
            # A retry cannot fix this, so the Check must not stay in progress.
            scan_error = f'HTTP_{status}'
            summary = (f"Scan incomplete: GitHub API returned HTTP {status} while preparing the scan "
                       "(for example, the commit or pull request is no longer readable). "
                       "No clean result was issued.")
        else:
            scan_error = type(e).__name__
            summary = "Scan incomplete: scanner, archive, or GitHub API error. No clean result was issued."
        log.error("pipeline error type=%s", scan_error)
    finally:
        if not defer_completion:
            _safe_complete()
    return {'conclusion': conclusion, 'scan_error': scan_error}

def _run_reserved_scan(*args):
    try:
        run_semgrep_pipeline(*args)
    finally:
        SCAN_SLOTS.release()


from job_payload import pr_job, identifier as queue_identifier, sha as queue_sha, branch as queue_branch

# ---------------- Startup / Health ----------------
@app.get("/health", include_in_schema=False)
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "prsec-webhook", "uptime_s": int(time.time() - BOOT_TS), "has_secret": bool(SECRETS)}

@app.get("/ready", include_in_schema=False)
def ready():
    if MODE == "durable":
        from job_store import JobStore
        store = JobStore(JOB_DB)
        if not SECRETS or not ALLOWED_REPOSITORY or not ALLOWED_INSTALLATION_ID or not store.ready():
            raise HTTPException(503, "Worker unavailable or configuration incomplete")
        status = store.status()
        return {'ready': True, 'mode': MODE, 'degraded': status['needs_attention'],
                'queue': status['counts'], 'cooldown_until': status['cooldown_until']}
    return {"ready": True, "mode": MODE}


# ---------------- Webhook ----------------
@app.post("/webhook")
async def webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_hub_signature: Optional[str] = Header(None, alias="X-Hub-Signature"),
    x_github_hook_id: Optional[str] = Header(None, alias="X-GitHub-Hook-ID"),
    x_github_target: Optional[str] = Header(None, alias="X-GitHub-Hook-Installation-Target-Type"),
):
    if not SECRETS:
        raise HTTPException(503, "Webhook secret is not configured")
    if MODE == "durable" and (not ALLOWED_REPOSITORY or not ALLOWED_INSTALLATION_ID):
        raise HTTPException(503, "Deployment repository scope is not configured")
    body_buffer = bytearray()
    async for chunk in request.stream():
        if len(body_buffer) + len(chunk) > MAX_WEBHOOK_BYTES:
            raise HTTPException(413, "Webhook payload too large")
        body_buffer.extend(chunk)
    body = bytes(body_buffer)
    provided = x_hub_signature_256 or ""
    if not any(hmac.compare_digest(provided, _hmac_sig(secret, body, "sha256")) for secret in SECRETS):
        raise HTTPException(401, "Invalid signature")
    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("Expected object")
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid JSON object")

    log.info("delivery=%s event=%s len=%d hook_id=%s target=%s", x_github_delivery, x_github_event, len(body), x_github_hook_id, x_github_target)

    if x_github_event == "ping":
        return {"ok": True, "pong": True}

    if x_github_event == 'push' and MODE == 'durable':
        try:
            repo = payload['repository']
            owner, name = queue_identifier(repo['owner']['login']), queue_identifier(repo['name'])
            installation = int(payload['installation']['id'])
            ref = payload['ref']
            if not isinstance(ref, str) or type(payload.get('deleted', False)) is not bool:
                raise ValueError('Malformed push')
        except (KeyError, TypeError, ValueError):
            raise HTTPException(400, 'Malformed push payload')
        if f'{owner}/{name}' != ALLOWED_REPOSITORY or installation != ALLOWED_INSTALLATION_ID:
            raise HTTPException(403, 'Push is outside configured scope')
        if not ref.startswith('refs/heads/') or payload.get('deleted'):
            return {'ok': True, 'ignored': 'non-branch or deleted ref'}
        try:
            job = {'kind': 'base_push', 'base_owner': owner, 'base_repo': name,
                   'installation_id': installation, 'base_ref': queue_branch(ref[len('refs/heads/'):]),
                   'after': queue_sha(payload['after'])}
            if job['after'] == '0' * 40: raise ValueError('Invalid branch tip')
        except (KeyError, TypeError, ValueError):
            raise HTTPException(400, 'Malformed branch push')
        from job_store import JobStore
        try:
            key, created = JobStore(JOB_DB).enqueue(job)
        except OverflowError:
            raise HTTPException(503, 'Queue full; redeliver later')
        return {'ok': True, 'queued': created, 'job_id': key}

    if x_github_event == "pull_request":
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "edited", "ready_for_review"}:
            return {"ok": True, "ignored": action}
        try:
            job = pr_job(payload['pull_request'], payload['number'], payload.get('installation', {}).get('id') or 0)
            base_owner, base_repo = job['base_owner'], job['base_repo']
            head_owner, head_repo = job['head_owner'], job['head_repo']
            pr_number, head_sha, base_sha = job['pr'], job['head_sha'], job['base_sha']
            installation_id = job['installation_id']
        except Exception as e:
            log.error("payload parse error error_type=%s", type(e).__name__)
            raise HTTPException(400, "Malformed PR payload")

        if ALLOWED_REPOSITORY and f"{base_owner}/{base_repo}" != ALLOWED_REPOSITORY:
            raise HTTPException(403, "Repository is outside configured scope")
        if ALLOWED_INSTALLATION_ID and installation_id != ALLOWED_INSTALLATION_ID:
            raise HTTPException(403, "Installation is outside configured scope")
        if MODE == "durable":
            from job_store import JobStore
            # Only identifiers enter the queue; no raw body, tokens or credentials.
            if action == 'reopened':
                # GitHub preserves delivery identity on redelivery; real reopen events
                # get distinct identities even when the commit is unchanged.
                job['reopen_event'] = hashlib.sha256(x_github_delivery.encode()).hexdigest()
            try:
                key, created = JobStore(JOB_DB).enqueue(job)
            except OverflowError:
                raise HTTPException(503, "Queue full; redeliver later")
            return {"ok": True, "queued": created, "job_id": key, "head": head_sha}

        if not SCAN_SLOTS.acquire(blocking=False):
            raise HTTPException(503, "Scanner busy; retry delivery later")
        # Acquire token
        try:
            token = _get_installation_token(installation_id)
        except Exception as e:
            log.error("token acquisition failed error_type=%s", type(e).__name__)
            SCAN_SLOTS.release()
            raise HTTPException(502, "Token acquisition failed")

        # Create Check Run (fallback on perms)
        try:
            check_owner, check_repo, check_id = create_check_in_progress_with_fallback(
                base_owner, base_repo, head_owner, head_repo, head_sha,
                CHECK_NAME, f"{CHECK_NAME} results", "Scanning…", token, installation_id
            )
        except Exception as e:
            log.error("failed to create check run error_type=%s", type(e).__name__)
            SCAN_SLOTS.release()
            raise HTTPException(502, "Check run creation failed")

        # Launch the bounded background scanner
        background.add_task(
            _run_reserved_scan,
            base_owner, base_repo, head_owner, head_repo, pr_number, head_sha,
            installation_id, check_owner, check_repo, check_id, token,
        )


        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    return {"ok": True, "ignored_event": x_github_event}


# Offline Semgrep ruleset embedded (written to temp file at runtime)
from trusted_rules import OFFLINE_RULESET
