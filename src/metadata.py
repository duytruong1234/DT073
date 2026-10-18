"""Bước 5a – Download metadata: đọc CVEfixes.db -> bảng ứng viên cấp file (mỗi dòng = 1 file_change).

Xử lý các quan hệ nhiều-nhiều của CVEfixes (đã thấy trong dữ liệu thật):
  * 1 commit sửa nhiều CVE, 1 CVE có nhiều CWE  -> gộp thành danh sách `cve_ids`, `cwe_ids`
  * cùng 1 hash xuất hiện ở nhiều repo (fork)   -> `repo_urls` (danh sách), `repo_url` = repo chuẩn
    (file_change không có cột repo_url nên không phân biệt được fork – ghi lại để chống rò rỉ)

KHÔNG đọc code_before/code_after ở bước này (cột nén, rất lớn) – chỉ đọc `diff`.
"""
from __future__ import annotations

import sqlite3

import pandas as pd

BASE_SQL = """
SELECT fc.file_change_id, fc.hash, fc.filename, fc.old_path, fc.new_path, fc.change_type,
       fc.programming_language AS lang, fc.diff,
       CAST(fc.num_lines_added AS INTEGER) AS num_lines_added,
       CAST(fc.num_lines_deleted AS INTEGER) AS num_lines_deleted
FROM file_change fc
WHERE fc.hash IN (SELECT hash FROM fixes)
"""


def _table_exists(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def load_candidates(con: sqlite3.Connection, languages: list[str] | None = None,
                    code_languages: list[str] | None = None) -> pd.DataFrame:
    """languages: lọc file theo ngôn ngữ ngay khi đọc (None = đọc hết, để validate ghi lý do loại).
    code_languages: ngôn ngữ được tính là "mã nguồn" khi đếm n_code_files_in_commit."""
    sql = BASE_SQL
    params: list = []
    if languages:
        sql += f" AND fc.programming_language IN ({','.join('?' * len(languages))})"
        params += list(languages)
    files = pd.read_sql_query(sql, con, params=params)

    commits = pd.read_sql_query(
        "SELECT hash, repo_url, committer_date, merge, parents FROM commits", con)
    n_files = pd.read_sql_query(
        "SELECT hash, COUNT(*) AS n_files_in_commit FROM file_change GROUP BY hash", con)
    if code_languages:
        q = (f"SELECT hash, COUNT(*) AS n_code_files_in_commit FROM file_change "
             f"WHERE programming_language IN ({','.join('?' * len(code_languages))}) GROUP BY hash")
        n_code = pd.read_sql_query(q, con, params=list(code_languages))
    else:
        n_code = n_files.rename(columns={"n_files_in_commit": "n_code_files_in_commit"})
    fixes = pd.read_sql_query("SELECT DISTINCT cve_id, hash, repo_url FROM fixes", con)

    # --- repo theo hash (fork) ---
    repos = (commits.sort_values(["hash", "repo_url"])
             .groupby("hash", sort=False)
             .agg(repo_urls=("repo_url", lambda s: sorted(set(s))),
                  repo_url=("repo_url", "first"),
                  committer_date=("committer_date", "min"),
                  merge=("merge", "first"),
                  parents=("parents", "first"))
             .reset_index())

    # --- CVE & CWE theo hash ---
    if _table_exists(con, "cwe_classification"):
        cwe = pd.read_sql_query("SELECT DISTINCT cve_id, cwe_id FROM cwe_classification", con)
    else:
        cwe = pd.DataFrame(columns=["cve_id", "cwe_id"])
    fx = fixes.merge(cwe, on="cve_id", how="left")
    labels = (fx.groupby("hash")
              .agg(cve_ids=("cve_id", lambda s: sorted(set(s))),
                   cwe_ids=("cwe_id", lambda s: sorted({x for x in s if isinstance(x, str)})))
              .reset_index())

    df = (files.merge(repos, on="hash", how="left")
               .merge(labels, on="hash", how="left")
               .merge(n_files, on="hash", how="left")
               .merge(n_code, on="hash", how="left"))
    df["n_code_files_in_commit"] = df["n_code_files_in_commit"].fillna(0).astype(int)
    df["n_repos"] = df["repo_urls"].map(lambda x: len(x) if isinstance(x, list) else 0)
    df["n_cves"] = df["cve_ids"].map(lambda x: len(x) if isinstance(x, list) else 0)
    df["year"] = df["committer_date"].astype(str).str[:4]
    return df.sort_values("file_change_id", kind="stable").reset_index(drop=True)
