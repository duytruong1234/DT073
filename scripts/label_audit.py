"""D5 – Audit chất lượng nhãn thủ công (label quality).

1) Lấy mẫu:   python scripts/label_audit.py sample --n 200 --seed 42
   -> results/label_audit/audit_sheet_A.csv, audit_sheet_B.csv (cùng mẫu, mỗi người 1 file, KHÔNG xem bài nhau)
2) Hai người chấm độc lập, điền 2 cột:
      relevant  : 1 = hunk liên quan trực tiếp tới việc sửa lỗ hổng, 0 = không (refactor, test, docs…), ? = không rõ
      cwe_ok    : 1 = nhãn CWE phù hợp với thay đổi, 0 = không phù hợp, ? = không rõ
   Mô tả CWE xem cột cwe_name. KHÔNG chạy mã trong hunk.
3) Tính kết quả: python scripts/label_audit.py score
   -> results/label_audit/audit_result.json (tỷ lệ đúng, Cohen's κ, theo từng CWE)
"""
import argparse
import json
import os
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import pandas as pd  # noqa: E402

from cvefixes_db import connect  # noqa: E402
from utils import load_config  # noqa: E402

OUT = os.path.join("results", "label_audit")


def sample(args, cfg):
    hk = pd.read_parquet(os.path.join(cfg["paths"]["processed"], "hunks.parquet"))
    pool = hk[hk["in_topk"] & hk["is_rep_near"]]
    k = pool["label"].nunique()
    per = max(1, args.n // k)
    s = pool.groupby("label").sample(n=per, random_state=args.seed)   # mỗi lớp top-K có ≥ 500 hunk
    if len(s) < args.n:  # bù cho đủ n
        rest = pool.drop(s.index).sample(args.n - len(s), random_state=args.seed)
        s = pd.concat([s, rest])
    s = s.sample(frac=1, random_state=args.seed)  # xáo trộn để người chấm không thấy theo nhóm
    con = connect(cfg["paths"]["db"])
    names = dict(con.execute("SELECT cwe_id, cwe_name FROM cwe").fetchall())
    sheet = pd.DataFrame({
        "audit_id": range(1, len(s) + 1), "hunk_id": s["hunk_id"].values, "lang": s["lang"].values,
        "repo_url": s["repo_url"].values, "cve_ids": s["cve_ids"].map(lambda x: ";".join(x)).values,
        "label": s["label"].values, "cwe_name": s["label"].map(lambda c: names.get(c.replace("CWE-", ""), names.get(c, ""))).values,
        "section": s["section"].values,
        "removed_lines": s["removed"].str.slice(0, 2000).values, "added_lines": s["added"].str.slice(0, 2000).values,
        "relevant": "", "cwe_ok": "", "note": ""})
    os.makedirs(OUT, exist_ok=True)
    for who in ("A", "B"):
        sheet.to_csv(os.path.join(OUT, f"audit_sheet_{who}.csv"), index=False, encoding="utf-8-sig")
    print(f"Đã tạo {len(sheet)} mẫu -> {OUT}/audit_sheet_A.csv, audit_sheet_B.csv")


def kappa(a, b):
    from sklearn.metrics import cohen_kappa_score
    m = a.isin(["0", "1"]) & b.isin(["0", "1"])
    return (round(float(cohen_kappa_score(a[m], b[m])), 4) if m.sum() and a[m].nunique() + b[m].nunique() > 2
            else None), int(m.sum())


def score(args, cfg):
    A = pd.read_csv(os.path.join(OUT, "audit_sheet_A.csv"), dtype=str).fillna("")
    B = pd.read_csv(os.path.join(OUT, "audit_sheet_B.csv"), dtype=str).fillna("")
    assert (A["hunk_id"] == B["hunk_id"]).all(), "Hai file không cùng mẫu"
    res = {"n": len(A)}
    for col in ("relevant", "cwe_ok"):
        a, b = A[col].str.strip(), B[col].str.strip()
        k, n_both = kappa(a, b)
        agree = (a == b) & a.isin(["0", "1"])
        consensus_pos = (agree & (a == "1")).sum()
        res[col] = {"cohen_kappa": k, "n_both_answered": n_both,
                    "raw_agreement": round(float(agree.sum() / max(n_both, 1)), 4),
                    "rate_A": round(float((a == "1").sum() / max(a.isin(["0", "1"]).sum(), 1)), 4),
                    "rate_B": round(float((b == "1").sum() / max(b.isin(["0", "1"]).sum(), 1)), 4),
                    "consensus_positive_rate": round(float(consensus_pos / max(agree.sum(), 1)), 4)}
    A["both_ok"] = (A["cwe_ok"].str.strip() == "1") & (B["cwe_ok"].str.strip() == "1")
    res["cwe_ok_by_label"] = A.groupby("label")["both_ok"].mean().round(3).to_dict()
    with open(os.path.join(OUT, "audit_result.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


def heuristic(args, cfg):
    """Kiểm tra sơ bộ tự động bằng quy tắc (automated heuristic pre-check) trên đúng 200 mẫu audit_sheet_A.csv.
    Lưu riêng vào heuristic_audit_200.json (ghi rõ là tự động, KHÔNG thay thế 2 người chấm độc lập khi nộp).
    """
    import re
    hk = pd.read_parquet(os.path.join(cfg["paths"]["processed"], "hunks.parquet"))
    A = pd.read_csv(os.path.join(OUT, "audit_sheet_A.csv"), dtype=str).fillna("")
    m = A.merge(hk[["hunk_id", "filename", "n_removed", "n_added", "before", "after"]], on="hunk_id", how="left")

    non_func_pat = re.compile(r"(^|/)(test|tests|spec|__tests__|doc|docs|example|examples|changelog|news|readme)", re.I)
    sec_kw = re.compile(
        r"(null|free|alloc|bound|len|size|overflow|check|valid|sanitiz|escap|html|sql|query|prepare|"
        r"path|traversal|auth|perm|token|csrf|nonce|exec|cmd|shell|limit|timeout|cast|signed|unsigned|"
        r"if\s*\(|return\s+-?\d|throw|raise|error|err)",
        re.I,
    )

    rel_flags, cwe_flags, reasons = [], [], []
    for r in m.itertuples(index=False):
        fn = str(getattr(r, "filename", "") or "")
        rem = str(getattr(r, "removed_lines", "") or "")
        add = str(getattr(r, "added_lines", "") or "")
        diff_txt = f"{rem}\n{add}"
        if non_func_pat.search(fn):
            rel_flags.append(0)
            cwe_flags.append(0)
            reasons.append("test_or_doc_file")
        elif int(getattr(r, "n_removed", 0)) + int(getattr(r, "n_added", 0)) <= 1 and not sec_kw.search(diff_txt):
            rel_flags.append(0)
            cwe_flags.append(0)
            reasons.append("trivial_single_line_non_security")
        elif sec_kw.search(diff_txt):
            rel_flags.append(1)
            cwe_flags.append(1)
            reasons.append("security_check_or_fix_pattern")
        else:
            rel_flags.append(1)
            cwe_flags.append(0)
            reasons.append("code_change_without_explicit_cwe_indicator")

    m["heuristic_relevant"] = rel_flags
    m["heuristic_cwe_ok"] = cwe_flags
    m["heuristic_reason"] = reasons
    res = {
        "mode": "automated_heuristic_precheck (chỉ tham khảo sơ bộ, KHÔNG phải Cohen's kappa của người chấm)",
        "n": int(len(m)),
        "estimated_relevant_rate": round(float(sum(rel_flags) / max(len(rel_flags), 1)), 4),
        "estimated_cwe_match_rate": round(float(sum(cwe_flags) / max(len(cwe_flags), 1)), 4),
        "reason_breakdown": pd.Series(reasons).value_counts().to_dict(),
        "by_label_cwe_match": m.groupby("label")["heuristic_cwe_ok"].mean().round(3).to_dict(),
    }
    with open(os.path.join(OUT, "heuristic_audit_200.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["sample", "score", "heuristic"])
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    cfg = load_config()
    fn = {"sample": sample, "score": score, "heuristic": heuristic}[args.cmd]
    fn(args, cfg)


if __name__ == "__main__":
    main()

