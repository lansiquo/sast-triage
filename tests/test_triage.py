"""Triage: which findings a pull request introduced, and how urgent they are. Offline only."""
from pathlib import Path

import pytest

import app
from analyzers import semgrep_runner as runner
from analyzers.semgrep_runner import add_fingerprints, summarize_findings, to_github_annotations
from analyzers.triage import (added_lines, baseline_counts, changed_lines, gate, is_source_path, is_test_path, priority,
                              triage)

# Two hunks: line 2 changed, line 3 added, then line 22 changed further down.
PATCH = """@@ -1,4 +1,5 @@
 import os
-x = 1
+x = 2
+y = 3

 def f():
@@ -20,2 +21,2 @@ def g():
     a = 1
-    b = 2
+    b = 3
\\ No newline at end of file"""


ADDED_LINES = [
    (PATCH, {2, 3, 22}),                                          # every hunk is read
    ('@@ -0,0 +1,3 @@\n+a\n+b\n+c', {1, 2, 3}),                   # new file: all added
    ('@@ -5,2 +5,1 @@\n keep\n-gone', set()),                      # deletions add nothing
    ('@@ -1,2 +1,2 @@\r\n keep\r\n-x = 1\r\n+x = 2\r\n', {2}),     # CRLF rows read like LF
    # Missing or unreadable patch: unknown.
    (None, None), ('', None), (42, None), ('Binary files differ', None),
    ('@@ broken @@\n+x', None), ('@@ -1 +1 @@\n*odd', None),
]


def test_added_lines():
    for patch, expected in ADDED_LINES:
        assert added_lines(patch) == expected, repr(patch)


# Characters str.splitlines() treats as line breaks but Git, GitHub and Semgrep
# do not. All are legal inside a Python comment.
SPLITLINES_ONLY_BREAKS = ['\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85', ' ', ' ']


def test_unicode_line_breaks_cannot_shift_a_new_finding_to_pre_existing():
    # Line 2 adds a comment holding the character, line 3 the vulnerable call.
    # If the parser split on it, " x" would read as a context line and the
    # call would be recorded as line 4, leaving the finding on line 3 "pre-existing".
    for char in SPLITLINES_ONLY_BREAKS:
        patch = f'@@ -1,2 +1,4 @@\n import os\n+# note{char} x\n+os.system(cmd)\n def f():'
        assert added_lines(patch) == {2, 3}, repr(char)
        ranked = triage([finding('app.py', 3)], {'app.py': added_lines(patch)})
        assert ranked[0]['new'] and gate(ranked) == 'failure', repr(char)


HEADER_MISMATCHES = [
    '@@ -1,2 +1,2 @@\n keep\n+extra\n+too many',          # more new lines than declared
    '@@ -1,3 +1,3 @@\n keep\n-x\n+y',                     # hunk ends early
    '@@ -1 +1 @@\n-x\n-y\n+z',                            # more old lines than declared
    '@@ -1,2 +1,2 @@\n a\n@@ -9 +9 @@\n-x\n+y',          # header before the previous hunk is complete
    '@@ -0,0 +1 @@\n+a\n+b',                              # omitted count means one line
]


def test_hunk_that_disagrees_with_its_header_is_unknown():
    for patch in HEADER_MISMATCHES:
        assert added_lines(patch) is None, repr(patch)
        ranked = triage([finding('app.py', 50)], {'app.py': added_lines(patch)})
        assert ranked[0]['new'], repr(patch)


def test_renames_keep_only_their_edited_lines():
    cases = [
        ({'filename': 'b.py', 'status': 'renamed', 'changes': 0}, set()),
        ({'filename': 'b.py', 'status': 'renamed', 'changes': 1, 'patch': '@@ -1 +1 @@\n-x\n+y'}, {1}),
        ({'previous_filename': 'app/old.py', 'filename': 'app/new.py'}, set()),         # runtime to runtime
        ({'previous_filename': 'tests/old.py', 'filename': 'tests/new.py'}, set()),     # test to test
        # Runtime to test lowers priority; nothing to re-flag.
        ({'previous_filename': 'app/loader.py', 'filename': 'tests/loader.py'}, set()),
    ]
    for entry, expected in cases:
        entry = {'status': 'renamed', 'changes': 0, **entry}
        assert changed_lines(entry) == expected, entry


def test_moving_test_code_into_runtime_code_counts_as_entirely_new():
    for status, changes, patch in [
        ('renamed', 0, None),                          # moved without edits
        ('renamed', 1, '@@ -5 +5 @@\n-x\n+y'),         # moved with a one-line edit
        ('copied', 1, '@@ -5 +5 @@\n-x\n+y'),          # copied with an edit
    ]:
        entry = {'filename': 'app/loader.py', 'previous_filename': 'tests/loader.py',
                 'status': status, 'changes': changes, **({'patch': patch} if patch else {})}
        assert changed_lines(entry) is None, entry
        # pickle.loads on untouched line 3 was P2 in tests/; in runtime code it is a new P1.
        ranked = triage([finding('app/loader.py', 3)], {'app/loader.py': changed_lines(entry)})
        assert (ranked[0]['priority'], ranked[0]['new']) == ('P1', True) and gate(ranked) == 'failure', entry


def test_high_severity_in_conftest_fails_the_check():
    ranked = triage([finding('tests/conftest.py', 4)], {'tests/conftest.py': {4}})
    assert (ranked[0]['priority'], ranked[0]['test_code']) == ('P1', False) and gate(ranked) == 'failure'


def test_changed_file_list_keeps_each_files_changed_lines(monkeypatch):
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: [
        {'filename': 'a.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-x\n+y'},
        {'filename': 'big.py', 'status': 'modified'},
        {'filename': 'gone.py', 'status': 'removed', 'patch': '@@ -1 +0,0 @@\n-x'},
    ])
    assert app.list_changed_files('o', 'r', 1, 'fake', 1) == {'a.py': {1}, 'big.py': None}


def finding(path='app.py', line=1, end=None, severity='HIGH', **extra):
    """A finding shaped like run_semgrep's output."""
    return {'path': path, 'start_line': line, 'end_line': end or line, 'severity': severity,
            'rule_id': 'py-rule', 'title': 'Risk', 'message': 'Risk', 'fix': None, 'cwe': None,
            'owasp': None, 'confidence': None, 'likelihood': None, **extra}


def test_test_code_follows_pytest_and_django_naming():
    for path in ['tests/test_api.py', 'pkg/test/helpers.py', 'test_api.py', 'api_test.py', 'shop/tests.py']:
        assert is_test_path(path), path
    # Everything else, conftest.py included, is runtime code.
    for path in ['app.py', 'testing_utils.py', 'contest.py', 'latest.py', 'attestations/sign.py',
                 'conftest.py', 'tests/conftest.py', 'pkg/test/conftest.py',
                 # JavaScript conventions do not apply to Python files.
                 'spec/helpers.py', 'specs/run.py', 'e2e/run.py', '__tests__/x.py', 'cypress/x.py', 'api.test.py']:
        assert not is_test_path(path), path


def test_test_code_follows_javascript_naming():
    for path in ['__tests__/api.js', 'src/__tests__/Button.tsx', 'spec/user.js', 'specs/a.ts', 'e2e/login.ts',
                 'cypress/support/commands.js', 'src/api.test.js', 'src/Button.spec.tsx', 'lib/x.test.mjs',
                 'lib/x.spec.cjs', 'ui/App.test.jsx', 'test/e2e/integration/login_spec.js', 'tests/a.cjs',
                 'test_helpers.js']:
        assert is_test_path(path), path
    for path in ['src/app.js', 'src/testing.js', 'src/contest.ts', 'src/latest.jsx', 'test.js', 'spec.ts',
                 'src/attest.ts', 'src/inspect.js', 'src/test-utils.js', 'specification/a.js', 'e2e.js']:
        assert not is_test_path(path), path


def test_only_python_javascript_and_typescript_files_are_scanned():
    for path in ['app.py', 'a.js', 'b.jsx', 'c.mjs', 'd.cjs', 'e.ts', 'f.tsx', 'types.d.ts', 'src/deep/g.js']:
        assert is_source_path(path), path
    for path in ['README.md', 'styles.css', 'package.json', 'app.pyc', 'page.html', 'a.JS', 'script.sh', 'js', '.py.bak']:
        assert not is_source_path(path), path


def test_pipeline_scans_changed_javascript_and_typescript_files(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'MODE', 'local')
    for name in ('app.js', 'src/view.tsx', 'api.py', 'README.md', 'styles.css'):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text('x\n')
    monkeypatch.setattr(app, 'download_tarball', lambda *a: tmp_path)
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: dict.fromkeys(
        ['app.js', 'src/view.tsx', 'api.py', 'README.md', 'styles.css']))
    scanned = []
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: scanned.append(k['paths']) or [finding('app.js', 1)])
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
    app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake')
    assert scanned == [['app.js', 'src/view.tsx', 'api.py']]
    assert completed[0][3] == 'failure' and '`app.js:1`' in completed[0][5]


def test_pipeline_without_supported_files_is_neutral_and_missing_sources_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(app, 'MODE', 'local')
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: pytest.fail('must not scan'))
    monkeypatch.setattr(app, 'download_tarball', lambda *a: tmp_path)
    (tmp_path / 'README.md').write_text('x\n')
    for changed, conclusion, summary in [
        (['README.md', 'package.json'], 'neutral', 'No supported changed Python, JavaScript or TypeScript files'),
        (['README.md', 'gone.ts'], 'failure', 'Scan incomplete'),          # listed as changed, absent from the snapshot
        (['../outside.js'], 'failure', 'Scan incomplete'),                 # path escapes the snapshot
    ]:
        completed = []
        monkeypatch.setattr(app, 'list_changed_files', lambda *a, _c=changed: dict.fromkeys(_c))
        monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
        app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake')
        assert (completed[0][3], completed[0][5][:len(summary)]) == (conclusion, summary), changed


def test_priority_mirrors_sca_triage_and_low_ratings_drop_one_level():
    for args, ratings, expected in [
        (('CRITICAL', False), {}, 'P1'), (('HIGH', False), {}, 'P1'),
        (('HIGH', True), {}, 'P2'), (('MEDIUM', False), {}, 'P2'),
        (('MEDIUM', True), {}, 'P3'), (('LOW', False), {}, 'P3'), (('LOW', True), {}, 'P3'),
        # A rule that rates its own confidence or likelihood LOW drops one level.
        (('HIGH', False), {'confidence': 'LOW'}, 'P2'),
        (('HIGH', False), {'likelihood': 'LOW'}, 'P2'),
        (('MEDIUM', False), {'confidence': 'LOW'}, 'P3'),
        (('LOW', False), {'confidence': 'LOW'}, 'P3'),
        (('HIGH', False), {'confidence': 'HIGH', 'likelihood': 'MEDIUM'}, 'P1'),
    ]:
        assert priority(*args, **ratings) == expected, (args, ratings)


def test_findings_on_changed_lines_are_new_and_the_rest_pre_existing():
    ranked = triage([
        finding('app.py', 3),            # untouched line
        finding('app.py', 9, end=11),    # multi-line call; only its last line changed
        finding('big.py', 50),           # GitHub sent no diff for this file
        finding('other.py', 1),          # missing from the changed list
    ], {'app.py': {10, 11}, 'big.py': None})
    assert [(f['path'], f['start_line'], f['new']) for f in ranked] == [
        ('app.py', 9, True), ('big.py', 50, True), ('other.py', 1, True), ('app.py', 3, False)]


def test_triage_sorts_p1_first_then_new_before_pre_existing():
    ranked = triage([
        finding('tests/test_x.py', 1),         # high in test code: P2
        finding('app.py', 5, severity='LOW'),  # P3
        finding('app.py', 2),                  # P1, untouched
        finding('app.py', 8),                  # P1, changed
    ], {'app.py': {8}, 'tests/test_x.py': {1}})
    assert [(f['priority'], f['new'], f['start_line']) for f in ranked] == [
        ('P1', True, 8), ('P1', False, 2), ('P2', True, 1), ('P3', False, 5)]


def test_annotations_show_priority_and_status():
    first, second = to_github_annotations(triage(
        [finding('app.py', 8, cwe='CWE-78', owasp='A05:2025', fix='Pass a list'),
         finding('app.py', 2, confidence='LOW')], {'app.py': {8}}))
    assert first['title'] == '[P1, new] Risk'
    assert 'Priority: P1 (high severity, runtime code)' in first['raw_details']
    assert 'Status: new' in first['raw_details']
    assert all(line in first['raw_details'] for line in ('CWE: CWE-78', 'OWASP: A05:2025', 'Suggested fix: Pass a list'))
    assert second['title'] == '[P2, pre-existing] Risk'
    assert 'Rule confidence: LOW' in second['raw_details']
    assert 'did not change these lines' in second['raw_details']


def test_summary_counts_by_priority_and_status():
    counts, md = summarize_findings(triage(
        [finding('app.py', 8), finding('app.py', 2), finding('tests/test_x.py', 1)], {'app.py': {8}}))
    assert counts == {'P1': {'new': 1, 'pre-existing': 1}, 'P2': {'new': 1, 'pre-existing': 0},
                      'P3': {'new': 0, 'pre-existing': 0}}
    assert '| P1 | 1 | 1 |' in md


def test_rule_confidence_and_likelihood_are_read_from_metadata():
    result = {'path': 'app.py', 'check_id': 'r', 'start': {'line': 1}, 'end': {'line': 1},
              'extra': {'severity': 'ERROR', 'message': 'Risk',
                        'metadata': {'confidence': 'low', 'likelihood': ['not', 'a', 'rating']}}}
    [normalized] = runner._normalize_results([result])
    assert normalized['confidence'] == 'LOW' and normalized['likelihood'] is None


def test_gate_fails_only_on_findings_that_are_new_and_p1():
    p1_untouched, p2_new = triage([finding('app.py', 1), finding('app.py', 2, severity='MEDIUM')], {'app.py': {2}})
    assert gate([]) == gate([p1_untouched, p2_new]) == 'success'
    assert gate(triage([finding('app.py', 2)], {'app.py': {2}})) == 'failure'


def test_summary_lists_at_most_ten_new_p1_findings():
    _, md = summarize_findings(triage([finding('app.py', n) for n in range(1, 13)], {'app.py': None}))
    assert md.count('`app.py:') == 10 and '- and 2 more' in md


def run_pipeline(tmp_path, monkeypatch, findings, changed):
    """Run the real pipeline with GitHub and Semgrep mocked; return what it reported."""
    monkeypatch.setattr(app, 'MODE', 'local')
    (tmp_path / 'tests').mkdir()
    for name in ('app.py', 'tests/test_app.py'):
        (tmp_path / name).write_text('print(1)\n')
    monkeypatch.setattr(app, 'download_tarball', lambda *a: tmp_path)
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: changed)
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: findings)
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
    app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake')
    conclusion, title, summary, annotations = completed[0][3:7]
    return conclusion, title, summary, annotations


def test_pre_existing_p1_alone_passes_the_check(tmp_path, monkeypatch):
    conclusion, title, summary, annotations = run_pipeline(
        tmp_path, monkeypatch, [finding('app.py', 1)], {'app.py': {5}})
    assert conclusion == 'success' and title == '0 new P1 findings'
    assert '**Gate: PASS**' in summary
    assert annotations[0]['annotation_level'] == 'notice'


def test_new_p2_alone_passes_the_check(tmp_path, monkeypatch):
    conclusion, _, _, annotations = run_pipeline(
        tmp_path, monkeypatch, [finding('tests/test_app.py', 1)], {'tests/test_app.py': {1}})
    assert conclusion == 'success'
    assert annotations[0]['annotation_level'] == 'warning'


def test_new_p1_fails_the_check_and_comes_first(tmp_path, monkeypatch):
    conclusion, title, summary, annotations = run_pipeline(tmp_path, monkeypatch, [
        finding('app.py', 1), finding('app.py', 2, severity='MEDIUM'), finding('app.py', 3),
    ], {'app.py': {3}})
    assert conclusion == 'failure' and title == '1 new P1 finding'
    assert '**Gate: FAIL** — 1 new P1 finding' in summary and '`app.py:3` py-rule' in summary
    assert [a['annotation_level'] for a in annotations] == ['failure', 'notice', 'notice']
    assert annotations[0]['start_line'] == 3


# A finding on untouched lines is pre-existing only if the base version of the file has it too.

def test_untouched_finding_is_new_unless_the_base_version_has_it():
    head = [finding('app.py', 4, fingerprint='exec'), finding('app.py', 9, fingerprint='md5')]
    changed = {'app.py': {3}}                                    # neither finding's line was edited
    base = baseline_counts([finding('app.py', 8, fingerprint='md5')])   # the md5 call was there, one line higher
    by_line = {f['start_line']: (f['new'], f['new_because']) for f in triage(head, changed, base)}
    assert by_line == {4: (True, 'not in the base version'), 9: (False, None)}
    assert gate(triage(head, changed, base)) == 'failure'
    # Without a baseline only the changed lines decide, as before.
    assert [f['new'] for f in triage(head, changed)] == [False, False]
    # A different rule on the same lines is a different finding.
    other = baseline_counts([finding('app.py', 4, fingerprint='exec', rule_id='another-rule')])
    assert triage(head[:1], changed, other)[0]['new']


def test_baseline_matching_is_per_file_counted_and_fails_closed():
    twice = [finding('app.py', 2, fingerprint='x'), finding('app.py', 7, fingerprint='x')]
    once = baseline_counts([finding('app.py', 2, fingerprint='x')])
    # The base had this finding once: the second copy is new.
    assert [(f['start_line'], f['new']) for f in triage(twice, {'app.py': {20}}, once)] == [(7, True), (2, False)]
    # A copy on a changed line is new without using up the base's match.
    labels = {f['start_line']: f['new_because'] for f in triage(twice, {'app.py': {2}}, once)}
    assert labels == {2: 'changed lines', 7: None}
    # Another file's baseline does not count, and neither does an unknown one (missing or None).
    elsewhere = baseline_counts([finding('other.py', 2, fingerprint='x')])
    for baseline in (elsewhere, {}, {'app.py': None}):
        assert all(f['new'] for f in triage(twice, {'app.py': {20}}, baseline)), baseline
    # A finding without a fingerprint (its file could not be read) never matches.
    assert triage([finding('app.py', 2)], {'app.py': {20}}, baseline_counts([finding('app.py', 2)]))[0]['new']
    # Renames: the base finding is counted under the file's new name.
    renamed = baseline_counts([finding('old.py', 2, fingerprint='x')], {'old.py': 'app.py'})
    assert not triage(twice[:1], {'app.py': set()}, renamed)[0]['new']
    # Unknown changes still make everything new, whatever the base holds.
    assert triage(twice[:1], {'app.py': None}, once)[0]['new_because'] == 'changes unknown'


def test_fingerprints_ignore_line_numbers_and_indentation_but_not_content(tmp_path):
    (tmp_path / 'a.py').write_text('import os\nos.system(cmd)\n')
    (tmp_path / 'b.py').write_text('\n\nif ready:\n        os.system(cmd)   \n')
    (tmp_path / 'c.py').write_text('os.system(other)\n')
    found = add_fingerprints([finding('a.py', 2), finding('b.py', 4), finding('c.py', 1), finding('gone.py', 1)],
                             str(tmp_path))
    a, b, c, gone = (f['fingerprint'] for f in found)
    assert a == b and a != c and len(a) == 16 and gone is None


def run_pipeline_with_base(tmp_path, monkeypatch, head_text, base_text, scan, changed, compare=None):
    """The real pipeline with a head and a base snapshot; `scan(root)` plays Semgrep for one snapshot."""
    monkeypatch.setattr(app, 'MODE', 'local')
    head, base = tmp_path / 'head', tmp_path / 'base'
    for root, text in ((head, head_text), (base, base_text)):
        root.mkdir(parents=True)
        (root / 'app.py').write_text(text)
    downloads = []
    monkeypatch.setattr(app, 'download_tarball', lambda o, r, sha, *a: downloads.append(sha) or (head if sha == 'a' * 40 else base))
    monkeypatch.setattr(app, 'list_changed_files', lambda *a: changed)
    monkeypatch.setattr(app, '_get_json', compare or (lambda url, *a, **k: {'merge_base_commit': {'sha': 'c' * 40}}))
    monkeypatch.setattr(app, 'run_semgrep', lambda **k: scan(Path(k['repo_root'])))
    completed = []
    monkeypatch.setattr(app, 'complete_check_run', lambda *a: completed.append(a))
    app.run_semgrep_pipeline('o', 'r', 'o', 'r', 1, 'a' * 40, 1, 'o', 'r', 99, 'fake', base_sha='b' * 40)
    return completed[0][3:7], downloads


def test_pipeline_fails_when_a_change_elsewhere_introduces_a_finding_on_an_untouched_line(tmp_path, monkeypatch):
    # The pull request edits line 1 only; line 2 is the same text in both versions,
    # but only the head version produces the finding.
    scan = lambda root: [finding('app.py', 2)] if root.name == 'head' else []
    (conclusion, title, summary, annotations), downloads = run_pipeline_with_base(
        tmp_path, monkeypatch, 'cmd = "ls " + request.args["dir"]\nos.system(cmd)\n', 'cmd = "ls"\nos.system(cmd)\n',
        scan, {'app.py': {1}})
    assert conclusion == 'failure' and title == '1 new P1 finding'
    assert downloads == ['a' * 40, 'c' * 40]                      # the head, then the merge base
    assert annotations[0]['annotation_level'] == 'failure'
    assert 'these lines are unchanged, but the finding was not there before' in annotations[0]['raw_details']


def test_pipeline_keeps_a_finding_pre_existing_when_the_base_version_has_it(tmp_path, monkeypatch):
    scan = lambda root: [finding('app.py', 3 if root.name == 'head' else 2)]   # moved down one line, same text
    (conclusion, _, summary, annotations), _ = run_pipeline_with_base(
        tmp_path, monkeypatch, 'import os\n# note\nos.system(cmd)\n', 'import os\nos.system(cmd)\n',
        scan, {'app.py': {2}})
    assert conclusion == 'success' and '| P1 | 0 | 1 |' in summary
    assert 'the finding was already there' in annotations[0]['raw_details']


def test_pipeline_counts_everything_as_new_when_the_base_cannot_be_scanned_and_fails_closed_on_api_errors(
        tmp_path, monkeypatch):
    def scan(root):
        if root.name == 'base':
            raise runner.SemgrepInvocationError(2, ['semgrep'], '', 'base version does not parse')
        return [finding('app.py', 2)]
    (conclusion, _, summary, _), _ = run_pipeline_with_base(
        tmp_path, monkeypatch, 'x = 1\nos.system(cmd)\n', 'x = (\nos.system(cmd)\n', scan, {'app.py': {1}})
    assert conclusion == 'failure' and 'could not be scanned, so every finding counts as new' in summary

    for attempt, reply in enumerate(({'merge_base_commit': {'sha': 'not-a-sha'}}, {}, [])):
        (conclusion, _, summary, _), downloads = run_pipeline_with_base(
            tmp_path / str(attempt), monkeypatch, 'x = 1\nos.system(cmd)\n', 'x = 1\nos.system(cmd)\n',
            lambda root: [finding('app.py', 2)], {'app.py': {1}}, compare=lambda *a, _r=reply, **k: _r)
        assert conclusion == 'failure' and summary.startswith('Scan incomplete') and downloads == ['a' * 40]


def test_changed_file_list_records_where_each_file_was_before(monkeypatch):
    files = [{'filename': 'new.py', 'status': 'added', 'patch': '@@ -0,0 +1 @@\n+x'},
             {'filename': 'edited.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-a\n+b'},
             {'filename': 'src/moved.py', 'status': 'renamed', 'previous_filename': 'src/old.py', 'changes': 0},
             {'filename': 'gone.py', 'status': 'removed'}]
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: files)
    changed = app.list_changed_files('o', 'r', 1, 'fake', 1)
    assert changed == {'new.py': {1}, 'edited.py': {1}, 'src/moved.py': set()}
    assert changed.previous == {'edited.py': 'edited.py', 'src/moved.py': 'src/old.py'}
