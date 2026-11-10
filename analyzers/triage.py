"""Triage for Semgrep findings: new vs pre-existing, then P1/P2/P3.

The SAST counterpart of sca-triage's src/triage.js. Everything here is a pure
function: no network, no files, no scanner calls.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Set

# "@@ -12,4 +12,6 @@ optional context": the old file's hunk covers 4 lines from
# line 12, the new file's 6 lines from line 12. An omitted count means 1.
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}

# File types the service-owned rules cover. Everything else is never staged.
PYTHON_EXTENSIONS = (".py",)
JAVASCRIPT_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
SOURCE_EXTENSIONS = PYTHON_EXTENSIONS + JAVASCRIPT_EXTENSIONS

# Jest, Mocha, Jasmine, Cypress and Playwright folders; applied to JavaScript
# and TypeScript files only, so Python results do not change.
JAVASCRIPT_TEST_FOLDERS = {"__tests__", "spec", "specs", "e2e", "cypress"}


def is_source_path(path: str) -> bool:
    """A Python, JavaScript or TypeScript file: the only files that are scanned."""
    return path.endswith(SOURCE_EXTENSIONS)


def added_lines(patch: Optional[str]) -> Optional[Set[int]]:
    """Return the line numbers (in the new file) that a unified diff adds or changes.

    A changed line shows up in a diff as a removed line plus an added one, so
    every "+" line counts. None means "unknown": no patch, or one that does not
    parse. Callers treat unknown as "every line is new", so a bad diff can
    only over-report findings, never hide one.

    Rows are split on "\\n" only, the way Git, GitHub and Semgrep count lines.
    str.splitlines() would also split on form feeds, U+2028 and other
    characters that are legal inside Python comments and strings, shifting
    every later line number. Each hunk must also hold exactly the old and new
    line counts its header declares; anything else is unknown.
    """
    if not isinstance(patch, str) or not patch:
        return None
    rows = patch.split("\n")
    if rows[-1] == "":
        rows.pop()  # a trailing newline ends the last row; it is not a row
    lines: Set[int] = set()
    line = None
    old_left = new_left = 0
    for row in rows:
        if row.endswith("\r"):
            row = row[:-1]  # CRLF file
        header = HUNK_HEADER.match(row)
        if header:
            if old_left or new_left:
                return None  # previous hunk ended early
            old_count, start, new_count = header.groups()
            old_left = int(old_count) if old_count is not None else 1
            new_left = int(new_count) if new_count is not None else 1
            line = int(start)
        elif line is None:
            return None  # text before the first hunk header
        elif row.startswith("\\"):
            continue  # "\ No newline at end of file"
        elif row.startswith("+"):
            if not new_left:
                return None
            lines.add(line)
            line += 1
            new_left -= 1
        elif row.startswith(" ") or row == "":
            if not old_left or not new_left:
                return None
            line += 1  # unchanged context line
            old_left -= 1
            new_left -= 1
        elif row.startswith("-"):
            if not old_left:
                return None
            old_left -= 1  # removed line
        else:
            return None
    if line is None or old_left or new_left:
        return None  # no hunk, or the last hunk ended early
    return lines


def changed_lines(entry: Dict[str, Any]) -> Optional[Set[int]]:
    """Lines the pull request added or changed in one entry of GitHub's PR files list.

    GitHub leaves out `patch` for very large diffs, which gives None (unknown).
    A file that was only renamed has no patch either, but nothing in it changed.

    A file moved from test code to runtime code counts as entirely new
    (None), with or without edits: its findings were ranked as test code
    before, so the move is what makes them urgent.
    """
    if entry.get("status") in {"renamed", "copied"}:
        previous = entry.get("previous_filename")
        if isinstance(previous, str) and is_test_path(previous) and not is_test_path(entry.get("filename", "")):
            return None
    if entry.get("status") == "renamed" and entry.get("changes") == 0:
        return set()
    return added_lines(entry.get("patch"))


def is_test_path(path: str) -> bool:
    """Test code by Python and JavaScript naming conventions.

    Any file: a test/tests folder or a test_* name. Python (pytest and Django)
    also: *_test.py and tests.py. JavaScript and TypeScript (Jest, Mocha,
    Jasmine, Cypress, Playwright) also: a __tests__, spec, specs, e2e or
    cypress folder, or a *.test.* or *.spec.* name such as api.test.js or
    button.spec.tsx. The JavaScript conventions apply to JavaScript and
    TypeScript files only, so a Python file in a spec folder stays runtime code.

    conftest.py is never test code, even in a tests folder: pytest imports it
    as a plugin on every run, before any test is selected, so it is ranked
    like runtime code.
    """
    *folders, name = PurePosixPath(path).parts
    if name == "conftest.py":
        return False
    if (any(folder in {"test", "tests"} for folder in folders)
            or name.startswith("test_") or name.endswith("_test.py") or name == "tests.py"):
        return True
    if name.endswith(JAVASCRIPT_EXTENSIONS):
        parts = name.split(".")
        return (any(folder in JAVASCRIPT_TEST_FOLDERS for folder in folders)
                or (len(parts) > 2 and parts[-2] in {"test", "spec"}))
    return False


# P1: high/critical in runtime code. Fix before merging.
# P2: high/critical in test code, or medium in runtime code. Schedule it.
# P3: everything else. Batch it with routine cleanup.
# A rule that rates its own confidence or likelihood LOW drops one level.
def priority(severity: str, test_code: bool, confidence: Optional[str] = None,
             likelihood: Optional[str] = None) -> str:
    high = severity in {"CRITICAL", "HIGH"}
    if high and not test_code:
        level = 1
    elif high or (severity == "MEDIUM" and not test_code):
        level = 2
    else:
        level = 3
    if "LOW" in (confidence, likelihood):
        level = min(level + 1, 3)
    return f"P{level}"


# Why a finding counts as new. A pre-existing finding has no reason (None).
CHANGED_LINES = "changed lines"
NOT_IN_BASE = "not in the base version"
UNKNOWN_CHANGES = "changes unknown"


def baseline_counts(base_findings: List[Dict[str, Any]],
                    head_path: Optional[Dict[str, str]] = None) -> Dict[str, Counter]:
    """Count the findings in the base version of each file, keyed by the file's path in the head.

    `head_path` maps a base path to the head path of the same file (for renames). A
    finding is identified by its rule and the fingerprint of the lines it covers, so
    it is recognised in the head whatever line it has moved to.
    """
    counts: Dict[str, Counter] = {}
    for f in base_findings:
        path = (head_path or {}).get(f["path"], f["path"])
        counts.setdefault(path, Counter())[(f["rule_id"], f.get("fingerprint"))] += 1
    return counts


def triage(findings: List[Dict[str, Any]], changed: Dict[str, Optional[Set[int]]],
           baseline: Optional[Dict[str, Optional[Counter]]] = None) -> List[Dict[str, Any]]:
    """Label each finding new or pre-existing, give it a priority, and sort P1 first.

    `changed` comes from list_changed_files. A finding is new when any line it
    covers was added or changed. A file whose changes are unknown (None), or
    that is missing from `changed`, counts as entirely new.

    `baseline` (from baseline_counts) holds the findings of each changed file's
    base version. With it, a finding on untouched lines is pre-existing only if
    the base version has it too: a change elsewhere in the file (a variable that
    now carries request data, a new import) can make an untouched line match, and
    that finding was introduced by the change. A file missing from `baseline`, or
    mapped to None, has an unknown base version, so its findings are new. Without
    a baseline (None) only the changed lines decide.
    """
    remaining = {path: Counter(counts) for path, counts in (baseline or {}).items() if counts is not None}
    ranked = []
    # In file and line order, so the same finding listed twice is matched to the base predictably.
    for f in sorted(findings, key=lambda f: (f["path"], f["start_line"], f["end_line"], f["rule_id"])):
        lines = changed.get(f["path"])
        if lines is None:
            reason = UNKNOWN_CHANGES
        elif any(n in lines for n in range(f["start_line"], f["end_line"] + 1)):
            reason = CHANGED_LINES
        elif baseline is None:
            reason = None
        else:
            key = (f["rule_id"], f.get("fingerprint"))
            counts = remaining.get(f["path"])
            if counts is not None and f.get("fingerprint") and counts[key] > 0:
                counts[key] -= 1
                reason = None
            else:
                reason = NOT_IN_BASE
        test_code = is_test_path(f["path"])
        ranked.append(dict(f, new=reason is not None, new_because=reason, test_code=test_code,
                           priority=priority(f["severity"], test_code, f.get("confidence"), f.get("likelihood"))))
    # P1 first, new before pre-existing, then by file and line.
    ranked.sort(key=lambda f: (PRIORITY_ORDER[f["priority"]], not f["new"], f["path"], f["start_line"]))
    return ranked


def gate(findings: List[Dict[str, Any]]) -> str:
    """The Check Run conclusion: it fails only when a finding is both new and P1."""
    return "failure" if any(f["new"] and f["priority"] == "P1" for f in findings) else "success"
