"""Live Semgrep checks for the service-owned rules. Every snippet is its own file in one scan; nothing is executed."""
from analyzers.semgrep_runner import run_semgrep
from trusted_rules import OFFLINE_RULESET


def scan(tmp_path, monkeypatch, sources):
    """Write {name: source}, scan them all at once, return {name: {rule ids}}."""
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    for name, source in sources.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(source + '\n')
    rules = tmp_path.parent / f'{tmp_path.name}-rules.yaml'
    rules.write_text(OFFLINE_RULESET)
    found = {name: set() for name in sources}
    for f in run_semgrep(sorted(sources), str(tmp_path), config=str(rules)):
        found[f['path']].add(f['rule_id'])
    return found


def test_files_in_folders_semgrep_ignores_by_default_are_still_scanned(tmp_path, monkeypatch):
    # Without the runner's empty .semgrepignore, Semgrep's built-in defaults
    # would skip these folders and the scan would fail closed.
    folders = ['tests', 'test', 'vendor', 'build', 'dist', 'node_modules/pkg']
    sources = {f'{folder}/case.py': 'eval(code)' for folder in folders}
    found = scan(tmp_path, monkeypatch, sources)
    assert found == {name: {'py-dangerous-eval'} for name in sources}
