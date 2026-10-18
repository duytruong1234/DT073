"""Bước 5b – Validate commits.

(1) Kiểm tra OFFLINE trên metadata: gán `status` = "ok" hoặc lý do loại (lý do ĐẦU TIÊN theo thứ tự
    ưu tiên -> dùng vẽ phễu coverage). Mọi ngưỡng lấy từ configs/base.yaml -> validate.
(2) Kiểm tra ONLINE (tùy chọn, trên mẫu): fetch đúng commit từ repo gốc bằng git (chỉ đọc lịch sử,
    KHÔNG checkout/biên dịch/chạy mã), so sánh danh sách file thay đổi với CVEfixes.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

import pandas as pd

HEX40 = re.compile(r"^[0-9a-f]{40}$")

# Thứ tự kiểm tra = thứ tự trong phễu coverage
REASONS = [
    "invalid_hash", "merge_commit", "no_cve", "language_excluded", "empty_diff", "binary_diff",
    "added_or_deleted_file", "tangled_commit", "too_many_lines",
]


def _is_true(v) -> bool:
    return str(v).strip().lower() in ("true", "1")


def _missing(v) -> bool:
    return v is None or (isinstance(v, float) and pd.isna(v))


def reason_for(row, cfg_validate: dict, languages: set | None) -> str:
    if not isinstance(row.hash, str) or not HEX40.match(row.hash):
        return "invalid_hash"
    if cfg_validate.get("drop_merge_commits", True) and _is_true(row.merge):
        return "merge_commit"
    if not isinstance(row.cve_ids, list) or not row.cve_ids:
        return "no_cve"
    if languages and row.lang not in languages:
        return "language_excluded"
    diff = row.diff
    if _missing(diff) or not str(diff).strip() or str(diff).strip() == "None":
        return "empty_diff"
    if str(diff).lstrip().startswith("Binary files") or "\x00" in str(diff)[:2000]:
        return "binary_diff"
    if cfg_validate.get("require_before_and_after", True):
        ct = str(row.change_type)
        if ct.endswith(("ADD", "DELETE")):
            return "added_or_deleted_file"
    count_col = ("n_code_files_in_commit" if cfg_validate.get("tangled_count", "code_files") == "code_files"
                 and hasattr(row, "n_code_files_in_commit") else "n_files_in_commit")
    if (getattr(row, count_col) or 0) > cfg_validate.get("max_files_per_commit", 10 ** 9):
        return "tangled_commit"
    churn = (row.num_lines_added or 0) + (row.num_lines_deleted or 0)
    if churn > cfg_validate.get("max_lines_changed_per_file", 10 ** 9):
        return "too_many_lines"
    return "ok"


def validate(df: pd.DataFrame, cfg_validate: dict, languages=None) -> pd.DataFrame:
    langs = set(languages) if languages else None
    out = df.copy()
    out["status"] = [reason_for(r, cfg_validate, langs) for r in out.itertuples(index=False)]
    return out


def funnel(df: pd.DataFrame) -> list[dict]:
    """Phễu coverage: còn lại bao nhiêu sau mỗi lý do loại (theo thứ tự REASONS)."""
    total = len(df)
    remaining = total
    rows = [{"stage": "candidates", "removed": 0, "remaining": total, "remaining_pct": 1.0}]
    counts = df["status"].value_counts().to_dict()
    for r in REASONS:
        n = int(counts.get(r, 0))
        remaining -= n
        rows.append({"stage": r, "removed": n, "remaining": remaining,
                     "remaining_pct": round(remaining / total, 4) if total else None})
    return rows


# ---------------------------------------------------------------- online (tùy chọn) ----
SAFE_URL = re.compile(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.\-]+/[\w.\-]+/?$")


def verify_commit_online(repo_url: str, sha: str, timeout: int = 120) -> dict:
    """Fetch commit (depth=2, không tải blob) và lấy danh sách file thay đổi.

    Trả về {"exists": bool, "files": [...], "error": str|None}. Không bao giờ ném ngoại lệ.
    Chỉ chấp nhận URL https của GitHub/GitLab/Bitbucket (chống đầu vào lạ trong dữ liệu).
    """
    if not SAFE_URL.match(repo_url or "") or not HEX40.match(sha or ""):
        return {"exists": False, "files": [], "error": "unsafe_or_invalid_input"}
    tmp = tempfile.mkdtemp(prefix="dt073_git_")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # không bao giờ hỏi mật khẩu
    try:
        def git(*args):
            return subprocess.run(["git", "-C", tmp, *args], capture_output=True, text=True,
                                  timeout=timeout, env=env)
        git("init", "-q", "--bare")
        r = git("fetch", "-q", "--depth=2", "--filter=blob:none", repo_url, sha)
        if r.returncode != 0:
            return {"exists": False, "files": [], "error": (r.stderr.strip().splitlines() or ["fetch_failed"])[-1]}
        r = git("diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--root", sha)
        files = sorted(set(r.stdout.split()))
        return {"exists": True, "files": files, "error": None}
    except subprocess.TimeoutExpired:
        return {"exists": False, "files": [], "error": "timeout"}
    except OSError as e:
        return {"exists": False, "files": [], "error": f"oserror:{e}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
