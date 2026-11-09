from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import re
import uuid
import threading
import tempfile
import certifi
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------- Public API ---------------------------------

@dataclass
class SemgrepInvocationError(Exception):
    exit_code: int
    cmd: List[str]
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return _fmt_semgrep_error(self.cmd, self.exit_code, self.stderr)


def run_semgrep(
    paths: List[str],
    repo_root: str,
    config: Optional[str] = None,
    exclude: Optional[List[str]] = None,
    timeout_s: int = 60,
) -> List[Dict[str, Any]]:
    """
    Run Semgrep on the provided file paths (relative to repo_root) and return normalized findings.

    Returns a list of dicts like:
      {
        "path": "app.py",
        "start_line": 12,
        "end_line": 12,
        "severity": "HIGH",          # CRITICAL/HIGH/MEDIUM/LOW
        "rule_id": "python.lang.subprocess.shell",
        "title": "Subprocess with shell=True",
        "message": "...",
        "fix": "subprocess.run([...], shell=False)",
        "cwe": "CWE-78",
        "owasp": "A01:2021"
      }
    """
    backend = os.getenv("PRSEC_SCANNER_BACKEND", "local")
    if backend not in {"local", "docker"}:
        raise ValueError("Unsupported scanner backend")
    if os.getenv("PRSEC_MODE", "local") == "durable" and backend != "docker":
        raise RuntimeError("Durable mode cannot run an unsandboxed scanner process")
    if not paths:
        return []

    container_backend = backend == "docker"
    semgrep_bin = "semgrep" if container_backend else _ensure_semgrep_available()
    cfg_value = _resolve_config(config, repo_root)

    # Allow comma/whitespace separated config list → multiple --config flags
    configs = _split_configs(cfg_value)

    # Excludes (hardened by default)
    excludes = list(exclude or [])
    for e in (".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "**/*.pyc", "**/*.pyo", "**/*.class"):
        if e not in excludes:
            excludes.append(e)

    # Repo-relative, de-duped includes
    rel_paths: List[str] = []
    seen = set()
    for p in paths:
        candidate = (Path(repo_root) / p).resolve()
        if Path(p).is_absolute() or not candidate.is_relative_to(Path(repo_root).resolve()):
            raise ValueError("Unsafe scan path")
        rp = _rel_to_repo_root(p, repo_root)
        if rp not in seen:
            rel_paths.append(rp)
            seen.add(rp)

    severity_floor = _severity_floor(os.getenv("PRSEC_SEMGREP_MIN_SEVERITY"))

    # Base command shared by chunks
    base_cmd = [
        semgrep_bin,
        "--metrics=off",
        "--json",
        "--jobs", "1",
        "--max-target-bytes", "1048576",
        "--timeout", str(timeout_s),
        "--skip-unknown-extensions",
        "--no-rewrite-rule-ids",
        "--disable-version-check",
        "--disable-nosem",
        "--quiet",
    ]
    scanner_command = os.getenv("PRSEC_SCANNER_COMMAND", "semgrep")
    if scanner_command not in {"semgrep", "opengrep"}:
        raise ValueError("Unsupported scanner command")
    if scanner_command == "opengrep":
        # Opengrep removed metrics support; its native CLI rejects this option.
        base_cmd.remove("--metrics=off")
    for c in configs:
        base_cmd += ["--config", c]
    for pat in excludes:
        base_cmd += ["--exclude", pat]

    # Give the scanner only selected source files, no attacker-controlled ignore
    # files, Git metadata, rules, credentials, or inherited application secrets.
    findings: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="prsec_scan_") as stage:
        stage_root = Path(stage)
        source_root = Path(repo_root).resolve()
        for name in rel_paths:
            source = (source_root / name).resolve()
            if not source.is_relative_to(source_root) or not source.is_file():
                raise ValueError("Scan target must be a file within the repository")
            if source.stat().st_size > 1024 * 1024:
                raise ValueError("Source file exceeds the supported 1 MiB scan limit")
            destination = stage_root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        # Without a .semgrepignore, Semgrep applies built-in defaults that skip
        # test/, tests/, vendor/, build/, dist/ and more, so a requested file
        # there would go unscanned. Every staged file was chosen; ignore none.
        (stage_root / ".semgrepignore").write_text("")
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG", "LC_ALL") if key in os.environ}
        env.update({"HOME": stage, "SEMGREP_SETTINGS_FILE": str(stage_root / "settings.yml"),
                    "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off",
                    "PYTHONDONTWRITEBYTECODE": "1", "SSL_CERT_FILE": certifi.where()})
        cmd = [*base_cmd, "."]
        container_name = None
        if container_backend:
            env["DOCKER_CONFIG"] = os.getenv("DOCKER_CONFIG", str(Path.home() / ".docker"))
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"):
                if key in os.environ:
                    env[key] = os.environ[key]
            if len(configs) != 1 or not Path(configs[0]).is_file():
                raise ValueError("Sandbox scans require exactly one service-owned local ruleset")
            stage_root.chmod(0o755)
            Path(configs[0]).chmod(0o644)
            for source in stage_root.rglob("*"):
                source.chmod(0o755 if source.is_dir() else 0o644)
            container_name = "prsec-" + uuid.uuid4().hex
            cmd = docker_scan_command(stage, configs[0], base_cmd, container_name)
        try:
            if container_backend:
                proc = _bounded_container_run(cmd, stage, env, timeout_s + 5)
            else:
                proc = _bounded_container_run(cmd=cmd, cwd=stage, env=env, timeout=timeout_s + 5)
        except subprocess.TimeoutExpired:
            raise SemgrepInvocationError(124, cmd, "", "Scanner timed out")
        finally:
            if container_name:
                # Killing only the docker CLI does not terminate its container.
                _confirm_container_cleanup(container_name, env)
        if proc.returncode not in (0, 1):
            raise SemgrepInvocationError(proc.returncode, cmd, "", "Scanner process failed")
        data = _parse_json_or_raise(proc.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list) or data.get("errors"):
            raise SemgrepInvocationError(65, cmd, "", "Incomplete or invalid scanner output")
        if proc.returncode == 1 and not data["results"]:
            raise SemgrepInvocationError(65, cmd, "", "Scanner exit status contradicts empty findings")
        scanned = data.get("paths", {}).get("scanned")
        if not isinstance(scanned, list) or not all(isinstance(name, str) for name in scanned):
            raise SemgrepInvocationError(65, cmd, "", "Scanner did not report target coverage")
        scanned_paths = {str(Path(name)) for name in scanned}
        if not set(rel_paths).issubset(scanned_paths):
            raise SemgrepInvocationError(65, cmd, "", "Scanner skipped requested source files")
        _validate_results(data["results"], cmd)
        for f in _normalize_results(data["results"]):
            f["path"] = str(Path(f["path"]))
            if f["path"] not in rel_paths:
                raise SemgrepInvocationError(65, cmd, "", "Unexpected finding path")
            if severity_floor and _sev_order(f["severity"]) < _sev_order(severity_floor):
                continue
            findings.append(f)

    return findings


def to_github_annotations(
    findings: List[Dict[str, Any]],
    max_per_file: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Convert triaged findings (see analyzers.triage) → GitHub Checks annotations.
    """
    out: List[Dict[str, Any]] = []
    per_file_count: Dict[str, int] = {}

    for f in findings:
        path = f["path"]
        if max_per_file:
            c = per_file_count.get(path, 0)
            if c >= max_per_file:
                continue
            per_file_count[path] = c + 1

        level = _annotation_level(f)
        title = f.get("title") or f.get("rule_id") or "Semgrep finding"
        label = "new" if f["new"] else "pre-existing"
        code = "test" if f["test_code"] else "runtime"
        meta: List[str] = [
            f"Priority: {f['priority']} ({f['severity'].lower()} severity, {code} code)",
            "Status: new (treat it as introduced by this pull request)" if f["new"]
            else "Status: pre-existing (this pull request did not change these lines)",
        ]
        for rating in ("confidence", "likelihood"):
            if f.get(rating):
                meta.append(f"Rule {rating}: {f[rating]}")
        if f.get("rule_id"):
            meta.append(f"Rule: {f['rule_id']}")
        if f.get("cwe"):
            meta.append(f"CWE: {f['cwe']}")
        if f.get("owasp"):
            meta.append(f"OWASP: {f['owasp']}")
        if f.get("fix"):
            meta.append(f"Suggested fix: {f['fix']}")

        annotation: Dict[str, Any] = {
            "path": path,
            "start_line": int(f["start_line"]),
            "end_line": int(f["end_line"]),
            "annotation_level": level,       # failure | warning | notice
            "title": f"[{f['priority']}, {label}] {title}"[:255],
            "message": (f.get("message") or title)[:60000],
        }
        if meta:
            annotation["raw_details"] = "\n".join(meta)
        out.append(annotation)

    return out


def summarize_findings(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, int]], str]:
    """
    Return (counts by priority, then new/pre-existing; markdown summary).
    """
    counts = {p: {"new": 0, "pre-existing": 0} for p in ("P1", "P2", "P3")}
    for f in findings:
        counts[f["priority"]]["new" if f["new"] else "pre-existing"] += 1

    new_p1 = [f for f in findings if f["new"] and f["priority"] == "P1"]
    if new_p1:
        plural = "" if len(new_p1) == 1 else "s"
        gate_lines = [f"**Gate: FAIL** — {len(new_p1)} new P1 finding{plural}:",
                      *(f"- `{f['path']}:{f['start_line']}` {f['rule_id']}" for f in new_p1[:10])]
        if len(new_p1) > 10:
            gate_lines.append(f"- and {len(new_p1) - 10} more")
    else:
        gate_lines = ["**Gate: PASS** — no new P1 findings. Anything else is annotated but doesn't fail the check."]

    md = [
        "### sast-triage — Semgrep summary",
        "",
        *gate_lines,
        "",
        "| Priority | New | Pre-existing |",
        "|---|---|---|",
        *(f"| {p} | {c['new']} | {c['pre-existing']} |" for p, c in counts.items()),
        "",
        "P1: high or critical severity in runtime code. P2: high or critical in test code, "
        "or medium in runtime code. P3: everything else. New: on lines this pull request "
        "added or changed.",
    ]
    return counts, "\n".join(md)

# --------------------------------- Internals ----------------------------------

def _confirm_container_cleanup(name, env):
    docker = shutil.which('docker') or 'docker'
    command = [docker, 'rm', '-f', name]
    try:
        removed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False, env=env)
        if removed.returncode == 0:
            return
        # --rm may already have removed it. A successful exact-name listing
        # establishes absence; daemon errors/unknown state do not.
        check = subprocess.run([docker, 'container', 'ls', '-a', '--filter', f'name=^/{name}$', '--format', '{{.ID}}'],
                               capture_output=True, text=True, timeout=15, check=False, env=env)
        if check.returncode == 0 and not check.stdout.strip():
            return
    except (OSError, subprocess.SubprocessError):
        pass
    logging.getLogger(__name__).error('container_cleanup_unconfirmed name=%s', name)
    raise SemgrepInvocationError(65, command, '', 'Container cleanup could not be confirmed')


def _bounded_container_run(cmd, cwd, env, timeout):
    """Drain both pipes while capping retained output; kill on overflow/timeout."""
    maximum = 8 * 1024 * 1024
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    lock = threading.Lock()
    process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def drain(stream, index):
        with stream:
            while chunk := stream.read(65536):
                with lock:
                    if sum(map(len, buffers)) + len(chunk) > maximum:
                        overflow.set()
                        process.kill()
                        return
                    buffers[index].extend(chunk)

    threads = [threading.Thread(target=drain, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        for thread in threads:
            thread.join(timeout=5)
    if overflow.is_set():
        raise SemgrepInvocationError(65, cmd, "", "Scanner output exceeded limit")
    return subprocess.CompletedProcess(cmd, process.returncode,
        buffers[0].decode("utf-8", errors="replace"), buffers[1].decode("utf-8", errors="replace"))


def verify_docker_sandbox():
    docker = shutil.which("docker")
    image = os.getenv("PRSEC_SCANNER_IMAGE", "")
    if not docker or not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", image):
        raise RuntimeError("Docker and a digest-pinned PRSEC_SCANNER_IMAGE are required")
    result = subprocess.run([docker, "info", "--format", "{{json .SecurityOptions}}"],
                            capture_output=True, text=True, timeout=15, check=True)
    if not any("rootless" in option for option in json.loads(result.stdout)):
        raise RuntimeError("Deployment worker requires a rootless Docker daemon")
    subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=15, check=True)


def docker_scan_command(stage, config, base_cmd, name):
    image = os.getenv("PRSEC_SCANNER_IMAGE", "")
    scanner_command = os.getenv("PRSEC_SCANNER_COMMAND", "semgrep")
    if scanner_command not in {"semgrep", "opengrep"}:
        raise ValueError("Unsupported scanner command")
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("Scanner image must be pinned by digest")
    # The host never mounts its Docker socket, home, .env, or App PEM in this container.
    scanner_args = list(base_cmd[1:])
    scanner_args[scanner_args.index("--config") + 1] = "/rules.yaml"
    return [shutil.which("docker") or "docker", "run", "--rm", "--pull=never", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=65532:65532", "--cpus=1", "--memory=768m", "--memory-swap=768m", "--pids-limit=128",
            "--ulimit", "nofile=256:256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=536870912,mode=1777",
            "--mount", f"type=bind,source={stage},target=/scan,readonly",
            "--mount", f"type=bind,source={config},target=/rules.yaml,readonly",
            "--workdir=/scan", "--env=HOME=/tmp", "--env=SEMGREP_SETTINGS_FILE=/tmp/settings.yml",
            "--env=SEMGREP_SEND_METRICS=off", "--env=SEMGREP_ENABLE_VERSION_CHECK=0",
            f"--entrypoint={scanner_command}", image, *scanner_args, "."]


def _launcher_is_usable(executable: str) -> bool:
    """Reject moved-venv scripts whose absolute shebang interpreter is gone."""
    try:
        with open(executable, "rb") as source:
            first_line = source.readline(4096)
        if first_line.startswith(b"#!"):
            interpreter = first_line[2:].decode("utf-8").strip().split()[0]
            return os.path.isabs(interpreter) and os.access(interpreter, os.X_OK)
        return True  # Native executable; launch errors remain fatal.
    except (OSError, UnicodeError, IndexError):
        return False


def _ensure_semgrep_available() -> str:
    """Prefer this Python's CLI, then PATH; never override an explicit choice."""
    explicit = os.getenv("SEMGREP_BIN")
    command = os.getenv("PRSEC_SCANNER_COMMAND", "semgrep")
    if command not in {"semgrep", "opengrep"}:
        raise ValueError("Unsupported scanner command")
    if explicit:
        candidates = [shutil.which(explicit)]
    else:
        directories = [str(Path(sys.executable).parent), *os.get_exec_path()]
        candidates = [shutil.which(command, path=directory) for directory in directories]
    for executable in dict.fromkeys(candidates):
        if executable and _launcher_is_usable(executable):
            return executable
    raise SemgrepInvocationError(
        exit_code=127,
        cmd=[explicit or command, "--version"],
        stdout="",
        stderr=(
            "No usable Semgrep launcher found (missing CLI or stale interpreter). "
            "Install semgrep in the project environment, or set SEMGREP_BIN to a working executable."
        ),
    )


def _resolve_config(cfg: Optional[str], repo_root: str) -> str:
    """
    Resolve config string:
      - if cfg is provided, use it
      - else use env SEMGREP_CONFIG (or typo SEMGRP_CONFIG), else 'p/ci'
      - local paths are made absolute relative to repo_root
      - registry IDs (p/... r/...), 'auto', and URLs are passed through
      - the returned string may contain multiple configs separated by ',' or whitespace
    """
    value = (cfg or os.getenv("SEMGREP_CONFIG") or os.getenv("SEMGRP_CONFIG") or "p/ci").strip()
    if not value:
        return "p/ci"

    # If it's a single local path, absolutize it; otherwise pass through
    # (run_semgrep will split on commas/whitespace)
    parts = _split_configs(value)
    absolutized: List[str] = []
    for p in parts:
        if _looks_like_local_path(p):
            absolutized.append(os.path.abspath(os.path.join(os.path.abspath(repo_root), p)))
        else:
            absolutized.append(p)
    return ",".join(absolutized)


def _split_configs(s: Optional[str]) -> List[str]:
    if not s:
        return ["p/ci"]
    # split on commas and/or whitespace, preserve order
    raw = str(s).replace("\n", " ").replace("\t", " ").split(",")
    tokens: List[str] = []
    for chunk in raw:
        for t in chunk.strip().split():
            if t:
                tokens.append(t)
    return tokens or ["p/ci"]


def _looks_like_local_path(s: str) -> bool:
    if s.startswith(("p/", "r/")):
        return False
    if s in {"auto", "semgrep-auto"}:
        return False
    if s.startswith(("http://", "https://")):
        return False
    return any(sep in s for sep in ("/", "\\")) or s.endswith((".yml", ".yaml"))


def _parse_json_or_raise(stdout: str) -> Dict[str, Any]:
    try:
        return json.loads(stdout or "{}")
    except json.JSONDecodeError as e:
        sample = (stdout or "").strip()[:800]
        raise SemgrepInvocationError(exit_code=65, cmd=["semgrep", "--json"], stdout=sample, stderr=str(e))


def _validate_results(results, cmd):
    """Reject malformed evidence before normalization or severity filtering."""
    allowed = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BLOCKER', 'ERROR', 'WARNING', 'WARN', 'INFO'}
    def invalid():
        raise SemgrepInvocationError(65, cmd, '', 'Malformed scanner finding evidence')
    for result in results:
        if not isinstance(result, dict): invalid()
        if not all(isinstance(result.get(key), str) and result[key].strip() for key in ('path', 'check_id')): invalid()
        extra = result.get('extra')
        if not isinstance(extra, dict): invalid()
        metadata = extra.get('metadata') or {}
        if not isinstance(metadata, dict): invalid()
        severity = metadata.get('severity') or extra.get('severity')
        if not isinstance(severity, str) or severity.strip().upper() not in allowed: invalid()
        if not isinstance(extra.get('message'), str): invalid()
        start, end = result.get('start'), result.get('end')
        if not isinstance(start, dict) or not isinstance(end, dict): invalid()
        first, last = start.get('line'), end.get('line')
        if type(first) is not int or type(last) is not int or first < 1 or last < first: invalid()


def _normalize_results(results: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for r in results:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}

        sev = _normalize_severity(meta.get("severity") or extra.get("severity") or "LOW")

        cwe_val = meta.get("cwe") or meta.get("cwe_id") or meta.get("cwe_id_vuln")
        if isinstance(cwe_val, list):
            cwe = ", ".join(map(str, cwe_val))
        elif isinstance(cwe_val, str):
            cwe = cwe_val
        else:
            cwe = None

        owasp_val = meta.get("owasp") or meta.get("owasp_category")
        if isinstance(owasp_val, list):
            owasp = ", ".join(map(str, owasp_val))
        elif isinstance(owasp_val, str):
            owasp = owasp_val
        else:
            owasp = None

        title = extra.get("message") or r.get("check_id") or "Semgrep finding"

        yield {
            "path": r.get("path"),
            "start_line": int(start.get("line") or 1),
            "end_line": int(end.get("line") or start.get("line") or 1),
            "severity": sev,
            "rule_id": r.get("check_id"),
            "title": title,
            "message": extra.get("message") or "",
            "fix": extra.get("fix") or meta.get("fix"),
            "cwe": cwe,
            "owasp": owasp,
            "confidence": _rule_rating(meta.get("confidence")),
            "likelihood": _rule_rating(meta.get("likelihood")),
        }


def _rule_rating(value: Any) -> Optional[str]:
    """Semgrep rules can rate their own confidence and likelihood: HIGH, MEDIUM or LOW."""
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def _rel_to_repo_root(path: str, repo_root: str) -> str:
    abs_repo = os.path.abspath(repo_root)
    abs_path = os.path.abspath(os.path.join(abs_repo, path))
    try:
        return os.path.relpath(abs_path, abs_repo)
    except ValueError:
        return os.path.basename(path)


def _normalize_severity(s: str) -> str:
    s = (s or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return s
    if s in {"BLOCKER"}:
        return "CRITICAL"
    if s in {"ERROR"}:
        return "HIGH"
    if s in {"WARNING", "WARN"}:
        return "MEDIUM"
    return "LOW"


def _severity_floor(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    val = (raw or "").strip().upper()
    if val in {"", "NONE", "OFF", "DISABLE"}:
        return None
    return _normalize_severity(val)


def _annotation_level(f: Dict[str, Any]) -> str:
    """Red only for what fails the check (new P1). New P2 warns; everything else is a notice."""
    if f["new"] and f["priority"] == "P1":
        return "failure"
    if f["new"] and f["priority"] == "P2":
        return "warning"
    return "notice"


def _sev_order(sev: str) -> int:
    m = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return m.get((sev or "").upper(), 1)


def _chunk(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _fmt_semgrep_error(cmd: List[str], code: int, stderr: str) -> str:
    return (
        f"Semgrep failed (exit={code}).\n"
        f"Command: {shlex.join(cmd)}\n"
        f"STDERR (truncated):\n{(stderr or '').strip()[:800]}"
    )
