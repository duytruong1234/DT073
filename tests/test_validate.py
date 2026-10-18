"""Unit test cho src/validate.py (offline) – mỗi lý do loại được kích hoạt đúng."""
import pandas as pd
import pytest

from validate import REASONS, funnel, validate, verify_commit_online

CFG = {"drop_merge_commits": True, "max_files_per_commit": 10,
       "max_lines_changed_per_file": 500, "require_before_and_after": True}
H = "a" * 40


def row(**kw):
    base = dict(hash=H, merge="False", cve_ids=["CVE-1"], lang="C", diff="@@ -1 +1 @@\n-x\n+y\n",
                change_type="ModificationType.MODIFY", n_files_in_commit=1,
                num_lines_added=1, num_lines_deleted=1)
    base.update(kw)
    return base


CASES = [
    (row(), "ok"),
    (row(hash="xyz"), "invalid_hash"),
    (row(merge="True"), "merge_commit"),
    (row(cve_ids=[]), "no_cve"),
    (row(lang="Markdown"), "language_excluded"),
    (row(diff=None), "empty_diff"),
    (row(diff="None"), "empty_diff"),
    (row(diff="Binary files a/x.png and b/x.png differ"), "binary_diff"),
    (row(change_type="ModificationType.ADD"), "added_or_deleted_file"),
    (row(change_type="ModificationType.DELETE"), "added_or_deleted_file"),
    (row(n_files_in_commit=50), "tangled_commit"),
    (row(num_lines_added=400, num_lines_deleted=200), "too_many_lines"),
]


@pytest.mark.parametrize("r,expected", CASES)
def test_reasons(r, expected):
    out = validate(pd.DataFrame([r]), CFG, ["C", "PHP"])
    assert out["status"].iloc[0] == expected


def test_priority_first_reason_wins():
    out = validate(pd.DataFrame([row(merge="True", diff=None)]), CFG, ["C"])
    assert out["status"].iloc[0] == "merge_commit"


def test_funnel_is_consistent():
    df = validate(pd.DataFrame([r for r, _ in CASES]), CFG, ["C", "PHP"])
    f = funnel(df)
    assert f[0]["remaining"] == len(CASES)
    assert f[-1]["remaining"] == (df["status"] == "ok").sum() == 1
    assert [x["stage"] for x in f[1:]] == REASONS


@pytest.mark.parametrize("url,sha", [
    ("file:///etc/passwd", H), ("https://evil.example.com/a/b", H),
    ("https://github.com/a/b;rm -rf /", H), ("https://github.com/a/b", "not-a-sha"),
])
def test_online_rejects_unsafe_input(url, sha):
    """Negative: URL/sha lạ trong dữ liệu không bao giờ được đưa vào git."""
    r = verify_commit_online(url, sha)
    assert r == {"exists": False, "files": [], "error": "unsafe_or_invalid_input"}
