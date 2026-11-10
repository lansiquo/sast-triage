from __future__ import annotations

"""Authenticated GitHub PR webhooks with bounded, trusted-rule Semgrep scans."""

import base64
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
import hashlib
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

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
from analyzers.semgrep_runner import (SemgrepInvocationError, add_fingerprints, run_semgrep, to_github_annotations,
                                      summarize_findings)
from analyzers.triage import baseline_counts, changed_lines, gate, is_source_path, needs_base, triage

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
MAX_SOURCE_BYTES = 1024 * 1024   # the scanner's per-file limit
MAX_FETCHED_FILES = 500          # changed source files read per version of a pull request
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
class ChangedFiles(dict):
    """list_changed_files' result, which also knows where each file was before the pull request.

    `previous` maps a file to its path in the base (its old name after a rename);
    a file the pull request added is not in it.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.previous: Dict[str, str] = {}


def list_changed_files(owner: str, repo: str, pr: int, token: str, install_id: Optional[int]) -> Dict[str, Optional[Set[int]]]:
    """Map each changed, non-deleted file to the lines the PR added or changed (None = unknown)."""
    files = ChangedFiles()
    page = 1
    while page <= 30:
        js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files", token, params={"per_page": 100, "page": page}, install_id=install_id)
        if not isinstance(js, list) or any(not isinstance(x, dict) or not isinstance(x.get('filename'), str) for x in js):
            raise RuntimeError('Invalid PR file list')
        if not js:
            break
        for x in js:
            if x.get('status') == 'removed':
                continue
            files[x['filename']] = changed_lines(x)
            if x.get('status') != 'added':
                old = x.get('previous_filename')
                files.previous[x['filename']] = old if isinstance(old, str) and old else x['filename']
        if len(js) < 100:
            break
        page += 1
    else:
        raise RuntimeError("PR file list exceeded supported pagination limit")
    return files

def fetch_files(owner: str, repo: str, ref: str, paths: List[str], token: str, install_id: Optional[int],
                workdir: Path, lenient: bool = False) -> Path:
    """Write `paths` as they are at commit `ref` under a new folder in `workdir`, and return the folder.

    Only these files are downloaded, one contents API call each: no repository archive
    is fetched or unpacked. A path must be relative and stay inside the folder, and
    GitHub must answer with a regular file at that exact path, of at most 1 MiB.
    Anything else (a symbolic link, a submodule, a larger file, a malformed answer)
    fails the scan. With `lenient` (the base versions), such a file is left out
    instead, and so is one that does not exist at `ref`; HTTP errors still raise.
    """
    if len(paths) > MAX_FETCHED_FILES:
        raise RuntimeError("Too many changed source files to fetch")
    root = Path(tempfile.mkdtemp(prefix="files_", dir=workdir))
    resolved = root.resolve()
    for path in paths:
        parts = PurePosixPath(path).parts
        target = root.joinpath(*parts)
        if (not parts or PurePosixPath(path).is_absolute() or ".." in parts or "\\" in path
                or not target.resolve().is_relative_to(resolved)):
            raise RuntimeError("Unsafe changed-file path")
        r = _gh_request("GET", f"{GITHUB_API}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}", token,
                        install_id=install_id, params={"ref": ref})
        if r.status_code == 404 and lenient:
            continue
        if r.status_code >= 400:
            log.error("GitHub GET failed status=%s", r.status_code)
        r.raise_for_status()
        data = _file_contents(r, path)
        if data is None:
            if lenient:
                continue
            raise RuntimeError("Changed source file is not a regular file of at most 1 MiB at the commit")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def _file_contents(r: requests.Response, path: str) -> Optional[bytes]:
    """The bytes of a contents API answer for one regular file, or None if it is anything else."""
    try:
        entry = r.json()
    except ValueError:
        return None
    if (not isinstance(entry, dict) or entry.get("type") != "file" or entry.get("path") != path
            or not isinstance(entry.get("size"), int) or not 0 <= entry["size"] <= MAX_SOURCE_BYTES
            or entry.get("encoding") != "base64" or not isinstance(entry.get("content"), str)):
        return None
    try:
        data = base64.b64decode(entry["content"].replace("\n", ""), validate=True)
    except ValueError:
        return None
    return data if len(data) == entry["size"] else None

def merge_base_sha(owner: str, repo: str, base_sha: str, head_sha: str, token: str, install_id: Optional[int]) -> str:
    """The commit GitHub diffs a pull request against: the merge base of its base and head."""
    # Page 2 with one commit per page: the file list and patches are only on page 1.
    js = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}", token,
                   params={"per_page": 1, "page": 2}, install_id=install_id)
    sha = js.get('merge_base_commit', {}).get('sha') if isinstance(js, dict) and isinstance(js.get('merge_base_commit'), dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise RuntimeError('Invalid compare response')
    return sha


def base_version_findings(owner: str, repo: str, base_sha: str, head_sha: str, changed: Dict[str, Optional[Set[int]]],
                          sources: List[str], token: str, install_id: Optional[int], workdir: Path,
                          config: str, exclude: List[str]) -> Optional[Dict[str, Counter]]:
    """Scan the base version of each changed source file and count its findings, keyed by the head path.

    The base version is the file at the pull request's merge base, fetched like the
    head files. A file that is missing there, larger than 1 MiB or not a regular file
    is left out, so its findings count as new. A file the pull request added has no
    base version. Returns None when the scanner cannot scan the base versions; API
    errors raise.
    """
    previous = getattr(changed, 'previous', None)
    if previous is None:
        previous = {path: path for path in changed}
    wanted: Dict[str, List[str]] = {}   # base path -> the head paths that came from it
    for path in sources:
        old = previous.get(path)
        if isinstance(old, str) and is_source_path(old):
            wanted.setdefault(old, []).append(path)
    if not wanted:
        return {}
    base_root = fetch_files(owner, repo, merge_base_sha(owner, repo, base_sha, head_sha, token, install_id),
                            sorted(wanted), token, install_id, workdir, lenient=True)
    staged = {old: paths for old, paths in wanted.items() if (base_root / old).is_file()}
    baseline: Dict[str, Counter] = {}
    if staged:
        try:
            found = add_fingerprints(run_semgrep(paths=sorted(staged), repo_root=str(base_root), config=config,
                                                 exclude=exclude, timeout_s=SEMGREP_TIMEOUT_S), str(base_root))
        except SemgrepInvocationError:
            return None
        counts = baseline_counts(found)
        for old, paths in staged.items():
            for path in paths:
                baseline[path] = Counter(counts.get(old, Counter()))
    return baseline


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
    base_sha: Optional[str] = None,
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
    current_base_sha = None   # the base commit GitHub reports for the pull request, when it was looked up
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
            # 1) The changed files and their diffs.
            changed = list_changed_files(base_owner, base_repo, pr, token, installation_id)
            if MODE == "durable":
                current = _get_json(f"{GITHUB_API}/repos/{base_owner}/{base_repo}/pulls/{pr}",
                                    token, install_id=installation_id)
                if _stale(current):
                    conclusion = "cancelled"
                    summary = "PR closed or changed during preparation; this job was not scanned."
                    return
                sha = current.get('base', {}).get('sha') if isinstance(current.get('base'), dict) else None
                if isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha):
                    current_base_sha = sha
            for name in changed:
                parts = PurePosixPath(name).parts
                if not parts or PurePosixPath(name).is_absolute() or ".." in parts or "\\" in name:
                    raise RuntimeError("Unsafe changed-file path")
            existing = [p for p in changed if is_source_path(p)]
            if not existing:
                conclusion = "neutral"
                summary = ("No supported changed Python, JavaScript or TypeScript files to scan "
                           "(deleted files are excluded).")
                return
            # 2) Only those files, at the exact PR head commit. GitHub keeps every PR head commit
            # in the base repository (refs/pull/N/head), so fork PRs are read with the
            # base-scoped installation token too. Their rules and ignore files are never used.
            repo_root = fetch_files(base_owner, base_repo, head_sha, existing, token, installation_id, tdp)
            if any(not (repo_root / p).is_file() for p in existing):
                raise RuntimeError('Changed source file is missing from the fetched files')
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
            findings = add_fingerprints(run_semgrep(
                paths=existing, repo_root=str(repo_root), config=cfg_value,
                exclude=ex, timeout_s=SEMGREP_TIMEOUT_S,
            ), str(repo_root))

            # 4b) A finding on untouched lines is pre-existing only if the file had it before the
            # pull request, so the base versions of those files (and only those) are scanned too.
            baseline = None
            base_note = ""
            compare_base = expected_base_sha or base_sha or current_base_sha
            to_compare = needs_base(findings, changed)
            if compare_base and to_compare:
                baseline = base_version_findings(base_owner, base_repo, compare_base, head_sha, changed, to_compare,
                                                 token, installation_id, tdp, cfg_value, ex)
                if baseline is None:
                    baseline = {}
                    base_note = ("\n\nThe base versions of the changed files could not be scanned, "
                                 "so every finding counts as new.")

            # A PR can close or advance while Semgrep is running.
            if MODE == 'durable':
                current = _get_json(f'{GITHUB_API}/repos/{base_owner}/{base_repo}/pulls/{pr}',
                                    token, install_id=installation_id)
                if _stale(current):
                    conclusion = 'cancelled'
                    summary = 'PR closed or changed during scanning; this result is stale.'
                    return

            # 5) Triage, summarize & annotate (sorted P1 first, so the cap never drops a P1 for a P3)
            findings = triage(findings, changed, baseline)
            counts, summary_md = summarize_findings(findings)
            summary_md += base_note
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

def _run_reserved_scan(*args, **kwargs):
    try:
        run_semgrep_pipeline(*args, **kwargs)
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
            base_sha=base_sha,
        )


        return {"ok": True, "event": "pull_request", "action": action, "pr": pr_number, "head": head_sha, "base": base_sha}

    return {"ok": True, "ignored_event": x_github_event}


# Offline Semgrep ruleset embedded (written to temp file at runtime)
from trusted_rules import OFFLINE_RULESET
