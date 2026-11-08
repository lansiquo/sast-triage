"""Triage: which findings a pull request introduced, and how urgent they are. Offline only."""
import pytest

import app
from analyzers import semgrep_runner as runner
from analyzers.semgrep_runner import summarize_findings, to_github_annotations
from analyzers.triage import added_lines, changed_lines, gate, is_test_path, priority, triage

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


def test_added_lines_reads_every_hunk():
    assert added_lines(PATCH) == {2, 3, 22}


def test_new_file_is_all_added_and_deletions_add_nothing():
    assert added_lines("@@ -0,0 +1,3 @@\n+a\n+b\n+c") == {1, 2, 3}
    assert added_lines("@@ -5,2 +5,1 @@\n keep\n-gone") == set()


@pytest.mark.parametrize('patch', [None, '', 42, 'Binary files differ', '@@ broken @@\n+x', '@@ -1 +1 @@\n*odd'])
def test_missing_or_unreadable_patch_is_unknown(patch):
    assert added_lines(patch) is None


# Characters str.splitlines() treats as line breaks but Git, GitHub and Semgrep
# do not. All are legal inside a Python comment.
SPLITLINES_ONLY_BREAKS = ['\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85', ' ', ' ']


@pytest.mark.parametrize('char', SPLITLINES_ONLY_BREAKS)
def test_unicode_line_breaks_cannot_shift_a_new_finding_to_pre_existing(char):
    # Line 2 adds a comment holding the character, line 3 the vulnerable call.
    # If the parser split on it, " x" would read as a context line and the
    # call would be recorded as line 4, leaving the finding on line 3 "pre-existing".
    patch = f'@@ -1,2 +1,4 @@\n import os\n+# note{char} x\n+os.system(cmd)\n def f():'
    assert added_lines(patch) == {2, 3}
    ranked = triage([finding('app.py', 3)], {'app.py': added_lines(patch)})
    assert ranked[0]['new'] and gate(ranked) == 'failure'


def test_crlf_patch_rows_are_read_like_lf():
    assert added_lines('@@ -1,2 +1,2 @@\r\n keep\r\n-x = 1\r\n+x = 2\r\n') == {2}


@pytest.mark.parametrize('patch', [
    '@@ -1,2 +1,2 @@\n keep\n+extra\n+too many',          # more new lines than declared
    '@@ -1,3 +1,3 @@\n keep\n-x\n+y',                     # hunk ends early
    '@@ -1 +1 @@\n-x\n-y\n+z',                            # more old lines than declared
    '@@ -1,2 +1,2 @@\n a\n@@ -9 +9 @@\n-x\n+y',          # header before the previous hunk is complete
    '@@ -0,0 +1 @@\n+a\n+b',                              # omitted count means one line
])
def test_hunk_that_disagrees_with_its_header_is_unknown(patch):
    assert added_lines(patch) is None
    ranked = triage([finding('app.py', 50)], {'app.py': added_lines(patch)})
    assert ranked[0]['new']


def test_pure_rename_has_no_changed_lines():
    assert changed_lines({'filename': 'b.py', 'status': 'renamed', 'changes': 0}) == set()
    assert changed_lines({'filename': 'b.py', 'status': 'renamed', 'changes': 1, 'patch': '@@ -1 +1 @@\n-x\n+y'}) == {1}


@pytest.mark.parametrize('status,changes,patch', [
    ('renamed', 0, None),                          # moved without edits
    ('renamed', 1, '@@ -5 +5 @@\n-x\n+y'),         # moved with a one-line edit
    ('copied', 0, None),
])
def test_moving_test_code_into_runtime_code_counts_as_entirely_new(status, changes, patch):
    entry = {'filename': 'app/loader.py', 'previous_filename': 'tests/loader.py',
             'status': status, 'changes': changes, **({'patch': patch} if patch else {})}
    assert changed_lines(entry) is None
    # pickle.loads on untouched line 3 was P2 in tests/; in runtime code it is a new P1.
    ranked = triage([finding('app/loader.py', 3)], {'app/loader.py': changed_lines(entry)})
    assert (ranked[0]['priority'], ranked[0]['new']) == ('P1', True) and gate(ranked) == 'failure'


@pytest.mark.parametrize('previous,filename', [
    ('app/old.py', 'app/new.py'),         # runtime to runtime
    ('tests/old.py', 'tests/new.py'),     # test to test
    ('app/loader.py', 'tests/loader.py'), # runtime to test lowers priority; nothing to re-flag
])
def test_other_pure_renames_stay_unchanged(previous, filename):
    assert changed_lines({'filename': filename, 'previous_filename': previous,
                          'status': 'renamed', 'changes': 0}) == set()


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


@pytest.mark.parametrize('path', ['tests/test_api.py', 'pkg/test/helpers.py', 'test_api.py',
                                  'api_test.py', 'shop/tests.py'])
def test_test_code_follows_pytest_and_django_naming(path):
    assert is_test_path(path)


@pytest.mark.parametrize('path', ['app.py', 'testing_utils.py', 'contest.py', 'latest.py', 'attestations/sign.py',
                                  'conftest.py', 'tests/conftest.py', 'pkg/test/conftest.py'])
def test_everything_else_is_runtime_code(path):
    assert not is_test_path(path)


@pytest.mark.parametrize('severity,test_code,expected', [
    ('CRITICAL', False, 'P1'), ('HIGH', False, 'P1'),
    ('HIGH', True, 'P2'), ('MEDIUM', False, 'P2'),
    ('MEDIUM', True, 'P3'), ('LOW', False, 'P3'), ('LOW', True, 'P3'),
])
def test_priority_mirrors_sca_triage(severity, test_code, expected):
    assert priority(severity, test_code) == expected


def test_low_rule_confidence_or_likelihood_drops_one_level():
    assert priority('HIGH', False, confidence='LOW') == 'P2'
    assert priority('HIGH', False, likelihood='LOW') == 'P2'
    assert priority('MEDIUM', False, confidence='LOW') == 'P3'
    assert priority('LOW', False, confidence='LOW') == 'P3'
    assert priority('HIGH', False, confidence='HIGH', likelihood='MEDIUM') == 'P1'


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
        [finding('app.py', 8), finding('app.py', 2, confidence='LOW')], {'app.py': {8}}))
    assert first['title'] == '[P1, new] Risk'
    assert 'Priority: P1 (high severity, runtime code)' in first['raw_details']
    assert 'Status: new' in first['raw_details']
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
