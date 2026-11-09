"""Offline portfolio demo: real scanner, local fixtures, no GitHub calls."""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import json
import tempfile
from pathlib import Path
from app import OFFLINE_RULESET
from analyzers.semgrep_runner import run_semgrep, summarize_findings, to_github_annotations
from analyzers.triage import added_lines, gate, triage

# A simulated pull request that changes two files.
#
# vulnerable.py (runtime code): adds `import random`, `import subprocess`,
# unsafe_command() and reset_token(). The md5 call was already there.
VULNERABLE_DIFF = """@@ -1,6 +1,16 @@
 # Deliberately insecure static-analysis fixture. Never execute this file.
 import hashlib
+import random
+import subprocess


 def unsafe_digest(data):
     return hashlib.md5(data).hexdigest()
+
+
+def unsafe_command(user_input):
+    return subprocess.run(user_input, shell=True)
+
+
+def reset_token():
+    return str(random.randint(100000, 999999))"""

# test_reports.py (test code): adds `import pickle` and load_snapshot().
# The tempfile.mktemp() call was already there.
TEST_DIFF = """@@ -1,6 +1,11 @@
 # Deliberately insecure static-analysis test fixture. Never execute this file.
+import pickle
 import tempfile
+
+
+def load_snapshot(blob):
+    return pickle.loads(blob)


 def scratch_path():
     return tempfile.mktemp()"""

PULL_REQUEST = {'vulnerable.py': VULNERABLE_DIFF, 'test_reports.py': TEST_DIFF}

# What the triage must decide for each finding: (priority, new).
EXPECTED = {
    'py-subprocess-shell-true': ('P1', True),                 # high, runtime, new: fails the check
    'py-weak-md5': ('P1', False),                             # high, runtime, already there: notice
    'py-random-for-secrets': ('P2', True),                    # medium, runtime, new: warning
    'py-insecure-deserialization-pickle-loads': ('P2', True), # high but test code, new: warning
    'py-tempfile-mktemp': ('P3', False),                      # medium, test code, already there: notice
}


def print_summary(title, findings, conclusion):
    """One line per triaged finding, then the Check Run's Markdown summary with the gate result."""
    print(f'\n{title}: {conclusion.upper()}')
    for f in findings:
        label = 'new' if f['new'] else 'pre-existing'
        print(f"  [{f['priority']}, {label}] {f['path']}:{f['start_line']}  {f['rule_id']}")
    print(summarize_findings(findings)[1])


def report(title, findings, conclusion):
    print_summary(title, findings, conclusion)
    print(json.dumps(to_github_annotations(findings), indent=2))


def main():
    root = Path(__file__).resolve().parent / 'demo' / 'fixtures'
    with tempfile.TemporaryDirectory(prefix='prsec_demo_') as temporary:
        config = Path(temporary) / 'rules.yaml'
        config.write_text(OFFLINE_RULESET)

        names = list(PULL_REQUEST)
        findings = run_semgrep(names, str(root), config=str(config))
        findings = triage(findings, {name: added_lines(diff) for name, diff in PULL_REQUEST.items()})
        conclusion = gate(findings)
        report('Pull request (' + ', '.join(names) + ')', findings, conclusion)
        labels = {f['rule_id']: (f['priority'], f['new']) for f in findings}
        assert labels == EXPECTED, labels
        assert conclusion == 'failure'

        findings = triage(run_semgrep(['clean.py'], str(root), config=str(config)), {'clean.py': None})
        conclusion = gate(findings)
        report('clean.py', findings, conclusion)
        assert not findings and conclusion == 'success'


if __name__ == '__main__':
    main()
