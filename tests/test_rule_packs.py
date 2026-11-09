"""The optional rule packs in rules/ must load in Semgrep; a parse error voids the whole scan."""
from pathlib import Path

import pytest
import yaml

from analyzers.semgrep_runner import run_semgrep

RULES = Path(__file__).resolve().parent.parent / 'rules'
PACKS = sorted(RULES.glob('*.yaml'))

# Written to a temporary directory and scanned, never executed.
SAMPLES = {
    'shell.py': 'import subprocess\nsubprocess.run(cmd, shell=True)\n',
    'spawn.js': 'const cp = require("child_process");\ncp.spawn(cmd, args, {shell: true});\n',
    'view.jsx': 'const V = () => <div className="x" dangerouslySetInnerHTML={{ __html: h }} />;\n',
    'workflow.yml': (
        'jobs:\n  build:\n    steps:\n'
        '      - uses: actions/checkout@v4\n'
        '      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0\n'
        '      - uses: ./local-action\n'
        '      - uses: docker://alpine:3.20\n'
        '      - uses: github/codeql-action/init@v3\n'
    ),
}


def _scan(tmp_path, monkeypatch, pack, names=tuple(SAMPLES)):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    for name in names:
        (tmp_path / name).write_text(SAMPLES[name])
    return run_semgrep(sorted(names), str(tmp_path), config=str(pack))


def test_rule_packs_found():
    assert {p.name for p in PACKS} >= {'security.yaml', 'rules.yaml', '.semgrep.yaml'}


@pytest.mark.parametrize('pack', PACKS, ids=lambda p: p.name)
def test_rule_pack_is_valid_yaml(pack):
    rules = yaml.safe_load(pack.read_text())['rules']
    assert rules and all({'id', 'message', 'severity', 'languages'} <= set(rule) for rule in rules)


@pytest.mark.parametrize('pack', PACKS, ids=lambda p: p.name)
def test_rule_pack_loads_in_semgrep(tmp_path, monkeypatch, pack):
    # run_semgrep raises on any scanner error, including rule parse errors.
    # Every pack has Python rules, so the Python sample is always a valid target.
    _scan(tmp_path, monkeypatch, pack, names=('shell.py',))


def test_security_pack_matches(tmp_path, monkeypatch):
    found = {(f['path'], f['start_line'], f['rule_id'])
             for f in _scan(tmp_path, monkeypatch, RULES / 'security.yaml')}
    assert ('shell.py', 2, 'py.subprocess.shell-true') in found
    assert ('spawn.js', 2, 'node.child_process.exec') in found
    assert ('view.jsx', 1, 'js.react.dangerouslysetinnerhtml') in found
    # Only floating refs on remote actions; SHA pins, local and docker actions pass.
    assert {(p, line) for p, line, rule in found if rule == 'gha.unpinned.actions'} == {
        ('workflow.yml', 4), ('workflow.yml', 8)}
