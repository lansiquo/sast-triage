"""Triage for Semgrep findings: new vs pre-existing, then P1/P2/P3.

The SAST counterpart of sca-triage's src/triage.js. Everything here is a pure
function: no network, no files, no scanner calls.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Set

# "@@ -12,4 +12,6 @@ optional context": the old file's hunk covers 4 lines from
# line 12, the new file's 6 lines from line 12. An omitted count means 1.
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}


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
    """pytest and Django naming: a test/tests folder, test_*.py, *_test.py or tests.py.

    conftest.py is never test code, even in a tests folder: pytest imports it
    as a plugin on every run, before any test is selected, so it is ranked
    like runtime code.
    """
    *folders, name = PurePosixPath(path).parts
    if name == "conftest.py":
        return False
    return (any(folder in {"test", "tests"} for folder in folders)
            or name.startswith("test_") or name.endswith("_test.py") or name == "tests.py")


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


def triage(findings: List[Dict[str, Any]], changed: Dict[str, Optional[Set[int]]]) -> List[Dict[str, Any]]:
    """Label each finding new or pre-existing, give it a priority, and sort P1 first.

    `changed` comes from list_changed_files. A finding is new when any line it
    covers was added or changed. A file whose changes are unknown (None), or
    that is missing from `changed`, counts as entirely new.
    """
    ranked = []
    for f in findings:
        lines = changed.get(f["path"])
        new = lines is None or any(n in lines for n in range(f["start_line"], f["end_line"] + 1))
        test_code = is_test_path(f["path"])
        ranked.append(dict(f, new=new, test_code=test_code,
                           priority=priority(f["severity"], test_code, f.get("confidence"), f.get("likelihood"))))
    # P1 first, new before pre-existing, then by file and line.
    ranked.sort(key=lambda f: (PRIORITY_ORDER[f["priority"]], not f["new"], f["path"], f["start_line"]))
    return ranked


def gate(findings: List[Dict[str, Any]]) -> str:
    """The Check Run conclusion: it fails only when a finding is both new and P1."""
    return "failure" if any(f["new"] and f["priority"] == "P1" for f in findings) else "success"
