"""Live Semgrep checks for the showcase rules. Every snippet is its own file in one scan; nothing is executed."""
from analyzers.semgrep_runner import run_semgrep
from demo_rules import SHOWCASE_RULESET

SHELL = 'demo-python-shell-command'
YAML = 'demo-python-unsafe-yaml'
TLS = 'demo-python-disabled-tls-verification'
SQL = 'demo-python-sql-string-concatenation'

# (source, rule the scan must report on line 1, or None for no finding)
CASES = [
    ("subprocess.run('echo ' + message, shell=True)", SHELL),
    ("subprocess.run(['/bin/echo', message], shell=False, check=True)", None),
    ('yaml.load(text, Loader=yaml.Loader)', YAML),
    ('yaml.load(text, Loader=yaml.UnsafeLoader)', YAML),
    ('yaml.unsafe_load(text)', YAML),
    ('yaml.safe_load(text)', None),
    ('yaml.load(text, Loader=yaml.SafeLoader)', None),
    ('requests.get(url, verify=False, timeout=5)', TLS),
    ('requests.post(url, verify=False)', TLS),
    ('requests.request("GET", url, verify=False)', TLS),
    ('requests.get(url, verify=False) # nosemgrep', TLS),  # suppression comments are ignored
    ('requests.get(url, verify=True, timeout=5)', None),
    ('requests.get(url, timeout=5)', None),
    ('other_client.get(url, verify=False)', None),
    ('db.execute("SELECT name FROM customers WHERE name = " + user_name)', SQL),
    ('db.execute("SELECT name FROM customers WHERE name = ?", (user_name,))', None),
    ('db.execute("SELECT name FROM customers")', None),
]


def test_showcase_rules_live(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    names = []
    for index, (source, _) in enumerate(CASES):
        name = f'case_{index:02d}.py'
        (tmp_path / name).write_text(source + '\n')
        names.append(name)
    rules = tmp_path / 'trusted.yaml'
    rules.write_text(SHOWCASE_RULESET)
    findings = run_semgrep(names, str(tmp_path), config=str(rules))
    got = {name: set() for name in names}
    for f in findings:
        assert f['start_line'] == 1
        got[f['path']].add(f['rule_id'])
    expected = {name: ({rule} if rule else set()) for name, (_, rule) in zip(names, CASES)}
    assert {CASES[int(n[5:7])][0]: v for n, v in got.items()} == {CASES[int(n[5:7])][0]: v for n, v in expected.items()}
