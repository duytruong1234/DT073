"""Bước 2c: Thống kê chất lượng dữ liệu ban đầu của CVEfixes.db (chỉ dùng thư viện chuẩn).

Đầu ra:
    data/reports/data_quality.json   – số liệu thô (để so sánh/tái lập)
    data/reports/data_quality.md     – bảng thống kê, chép vào chương Dữ liệu của báo cáo

Cách chạy:
    python scripts/data_report.py [--db data/db/CVEfixes.db]
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter

for _s in (sys.stdout, sys.stderr):  # tránh lỗi in tiếng Việt khi output bị chuyển hướng (cp1252)
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from cvefixes_db import connect, DEFAULT_DB  # noqa: E402

OUT_JSON = os.path.join("data", "reports", "data_quality.json")
OUT_MD = os.path.join("data", "reports", "data_quality.md")
NONSPECIFIC_CWE = ("NVD-CWE-Other", "NVD-CWE-noinfo")


def q(con, sql, *args):
    return con.execute(sql, args).fetchall()


def one(con, sql, *args):
    return con.execute(sql, args).fetchone()[0]


def has_col(con, table, col):
    return col in {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}


def quantiles(values, ps=(0.5, 0.9, 0.99)):
    v = sorted(x for x in values if x is not None)
    if not v:
        return {}
    return {f"p{int(p * 100)}": v[min(len(v) - 1, int(p * len(v)))] for p in ps} | {"max": v[-1]}


def build(con):
    r = {}
    tables = [t for (t,) in q(con, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\'")]
    r["row_counts"] = {t: one(con, f'SELECT COUNT(*) FROM "{t}"') for t in tables}

    # ---- Mức CVE / CWE ----
    r["n_cve_in_fixes"] = one(con, "SELECT COUNT(DISTINCT cve_id) FROM fixes")
    r["n_commits_in_fixes"] = one(con, "SELECT COUNT(DISTINCT hash) FROM fixes")
    r["n_repos_in_fixes"] = one(con, "SELECT COUNT(DISTINCT repo_url) FROM fixes")
    if "cwe_classification" in tables:
        cwe = Counter(dict(q(con, "SELECT cwe_id, COUNT(DISTINCT cve_id) FROM cwe_classification GROUP BY cwe_id")))
        n_cve_cwe = one(con, "SELECT COUNT(DISTINCT cve_id) FROM cwe_classification")
        per_cve = Counter(n for (n,) in q(con, "SELECT COUNT(*) FROM cwe_classification GROUP BY cve_id"))
        r["cwe"] = {
            "n_distinct_cwe": len(cwe),
            "n_cve_with_cwe": n_cve_cwe,
            "top25": cwe.most_common(25),
            "nonspecific": {k: cwe.get(k, 0) for k in NONSPECIFIC_CWE},
            "cve_only_nonspecific": one(con, f"""SELECT COUNT(*) FROM (SELECT cve_id FROM cwe_classification
                GROUP BY cve_id HAVING SUM(cwe_id NOT IN {NONSPECIFIC_CWE}) = 0)"""),
            "cwe_per_cve_hist": dict(sorted(per_cve.items())),
            "fixes_cve_without_cwe": one(con, """SELECT COUNT(DISTINCT cve_id) FROM fixes
                WHERE cve_id NOT IN (SELECT cve_id FROM cwe_classification)"""),
        }
    if "cve" in tables and has_col(con, "cve", "published_date"):
        r["cve_by_year"] = dict(q(con, "SELECT substr(published_date,1,4) y, COUNT(*) FROM cve GROUP BY y ORDER BY y"))

    # ---- Mức commit ----
    r["commits"] = {
        "fixes_rows_without_commit": one(con, """SELECT COUNT(*) FROM fixes
            WHERE hash || '|' || repo_url NOT IN (SELECT hash || '|' || repo_url FROM commits)"""),
        "commits_without_file_change": one(con, """SELECT COUNT(*) FROM commits
            WHERE hash NOT IN (SELECT DISTINCT hash FROM file_change)"""),
        "same_hash_multiple_repos": one(con, """SELECT COUNT(*) FROM (SELECT hash FROM commits
            GROUP BY hash HAVING COUNT(DISTINCT repo_url) > 1)"""),
        "by_year": dict(q(con, "SELECT substr(committer_date,1,4) y, COUNT(*) FROM commits GROUP BY y ORDER BY y")),
        "top_repos": q(con, "SELECT repo_url, COUNT(*) n FROM commits GROUP BY repo_url ORDER BY n DESC LIMIT 15"),
    }
    if has_col(con, "commits", "merge"):
        r["commits"]["merge_commits"] = one(con, "SELECT COUNT(*) FROM commits WHERE merge IN ('True','1',1)")
    files_per_commit = [n for (n,) in q(con, "SELECT COUNT(*) FROM file_change GROUP BY hash")]
    r["commits"]["files_per_commit"] = quantiles(files_per_commit)
    r["commits"]["commits_gt_10_files"] = sum(n > 10 for n in files_per_commit)

    # ---- Mức file ----
    fc = {"by_language": q(con, """SELECT programming_language, COUNT(*) FROM file_change
                                   GROUP BY 1 ORDER BY 2 DESC"""),
          "by_change_type": q(con, "SELECT change_type, COUNT(*) FROM file_change GROUP BY 1 ORDER BY 2 DESC")}
    none_expr = "({c} IS NULL OR (length({c}) < 40 AND unz({c}) IN ('None','')))"
    fc["code_before_missing"] = one(con, f"SELECT SUM({none_expr.format(c='code_before')}) FROM file_change")
    fc["code_after_missing"] = one(con, f"SELECT SUM({none_expr.format(c='code_after')}) FROM file_change")
    fc["diff_empty"] = one(con, "SELECT COUNT(*) FROM file_change WHERE diff IS NULL OR trim(diff)='' OR diff='None'")
    churn = [a + d for a, d in q(con, "SELECT CAST(num_lines_added AS INT), CAST(num_lines_deleted AS INT) FROM file_change")
             if a is not None and d is not None]
    fc["lines_changed_per_file"] = quantiles(churn)

    # Trùng lặp sơ bộ: cùng nội dung diff (exact) – đo chính thức ở bước dedup trên hunk
    seen, dup, total = Counter(), 0, 0
    for (d,) in con.execute("SELECT diff FROM file_change WHERE diff IS NOT NULL AND trim(diff)<>''"):
        h = hashlib.sha1(d.encode("utf-8", "surrogatepass")).digest()
        dup += seen[h] > 0
        seen[h] += 1
        total += 1
    fc["diff_exact_duplicates"] = {"rows": total, "duplicates": dup,
                                   "duplicate_rate": round(dup / total, 4) if total else None}
    r["file_change"] = fc

    if "method_change" in tables:
        r["method_change"] = {"by_before_change": q(con, "SELECT before_change, COUNT(*) FROM method_change GROUP BY 1")}
    return r


def pct(a, b):
    return f"{a / b:.1%}" if b else "-"


def to_markdown(r, manifest):
    L = ["# Thống kê dữ liệu CVEfixes (tự sinh bởi `scripts/data_report.py`)", ""]
    if manifest:
        f = next(iter(manifest.get("files", {}).items()), (None, {}))
        db = manifest.get("derived", {}).get("CVEfixes.db", {})
        L += ["## Nguồn & phiên bản", "",
              "| Mục | Giá trị |", "|---|---|",
              f"| Dataset | {manifest.get('dataset')} {manifest.get('version')} ({manifest.get('coverage')}) |",
              f"| DOI | {manifest.get('doi')} |",
              f"| Giấy phép | {manifest.get('license')} |",
              f"| Ngày tải | {manifest.get('downloaded_at')} |",
              f"| File gốc | `{f[0]}` – MD5 `{f[1].get('md5')}` – SHA‑256 `{f[1].get('sha256')}` |",
              f"| CSDL dẫn xuất | `CVEfixes.db` – SHA‑256 `{db.get('sha256')}` – cột nén: {db.get('compressed_columns')} |",
              ""]
    L += ["## Số dòng theo bảng", "", "| Bảng | Số dòng |", "|---|---:|"]
    L += [f"| {t} | {n:,} |" for t, n in r["row_counts"].items()]
    L += ["", f"CVE trong `fixes`: **{r['n_cve_in_fixes']:,}** · commit: **{r['n_commits_in_fixes']:,}** · "
          f"repo: **{r['n_repos_in_fixes']:,}**", ""]
    if "cwe" in r:
        c = r["cwe"]
        n = c["n_cve_with_cwe"]
        L += ["## Nhãn CWE", "",
              f"- Số CWE khác nhau: **{c['n_distinct_cwe']}**; CVE có nhãn CWE: **{n:,}**",
              f"- `NVD-CWE-Other`: {c['nonspecific']['NVD-CWE-Other']:,} CVE · `NVD-CWE-noinfo`: "
              f"{c['nonspecific']['NVD-CWE-noinfo']:,} CVE",
              f"- CVE **chỉ** có nhãn không cụ thể: **{c['cve_only_nonspecific']:,}** ({pct(c['cve_only_nonspecific'], n)})",
              f"- CVE trong `fixes` không có CWE: {c['fixes_cve_without_cwe']:,}",
              f"- Số CWE / CVE: {c['cwe_per_cve_hist']}", "",
              "| # | CWE | Số CVE | Tỷ lệ |", "|---:|---|---:|---:|"]
        L += [f"| {i} | {k} | {v:,} | {pct(v, n)} |" for i, (k, v) in enumerate(c["top25"], 1)]
        L += [""]
    cm = r["commits"]
    L += ["## Commit", "",
          f"- Dòng `fixes` không khớp commit: {cm['fixes_rows_without_commit']:,}",
          f"- Commit không có file_change: {cm['commits_without_file_change']:,}",
          f"- Cùng hash xuất hiện ở nhiều repo (fork): {cm['same_hash_multiple_repos']:,}",
          f"- Merge commit: {cm.get('merge_commits', '-')}",
          f"- Số file / commit: {cm['files_per_commit']} · commit > 10 file (nghi tangled): {cm['commits_gt_10_files']:,}",
          "", "| Repo | Số commit |", "|---|---:|"]
    L += [f"| {u} | {n:,} |" for u, n in cm["top_repos"]]
    fc = r["file_change"]
    total = r["row_counts"].get("file_change", 0)
    L += ["", "## File thay đổi", "",
          f"- Thiếu `code_before` (file mới): {fc['code_before_missing']:,} ({pct(fc['code_before_missing'], total)})",
          f"- Thiếu `code_after` (file bị xóa): {fc['code_after_missing']:,} ({pct(fc['code_after_missing'], total)})",
          f"- Diff rỗng: {fc['diff_empty']:,}",
          f"- Số dòng thay đổi / file: {fc['lines_changed_per_file']}",
          f"- **Trùng lặp diff (exact, sơ bộ)**: {fc['diff_exact_duplicates']['duplicates']:,} / "
          f"{fc['diff_exact_duplicates']['rows']:,} = **{fc['diff_exact_duplicates']['duplicate_rate']}**",
          "", "| Ngôn ngữ | Số file | Tỷ lệ |", "|---|---:|---:|"]
    L += [f"| {k} | {v:,} | {pct(v, total)} |" for k, v in fc["by_language"][:20]]
    L += ["", "| change_type | Số file |", "|---|---:|"] + [f"| {k} | {v:,} |" for k, v in fc["by_change_type"]]
    L += ["", "## Commit theo năm", "", "| Năm | Số commit |", "|---|---:|"]
    L += [f"| {y} | {n:,} |" for y, n in cm["by_year"].items()]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--out-json", default=OUT_JSON)
    ap.add_argument("--out-md", default=OUT_MD)
    args = ap.parse_args()
    con = connect(args.db)
    print("Đang thống kê (vài phút) ...")
    r = build(con)
    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=2)
    manifest = None
    if os.path.exists(os.path.join("data", "MANIFEST.json")):
        with open(os.path.join("data", "MANIFEST.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    os.makedirs(os.path.dirname(args.out_md), exist_ok=True)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(to_markdown(r, manifest))
    print(f"OK -> {args.out_json}, {args.out_md}")


if __name__ == "__main__":
    main()
