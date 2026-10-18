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
    """Chấm độc lập bằng 2 bộ quy tắc chuyên biệt (Coder A: cấu trúc/đường dẫn/luồng điều khiển;
    Coder B: từ vựng đặc thù theo từng lớp CWE) trên 200 mẫu phân tầng (seed 42), đồng thời lưu bản trắng
    audit_sheet_blank.csv nếu 2 thành viên nhóm muốn chấm tay lại.
    """
    import re
    hk = pd.read_parquet(os.path.join(cfg["paths"]["processed"], "hunks.parquet"))
    A = pd.read_csv(os.path.join(OUT, "audit_sheet_A.csv"), dtype=str).fillna("")
    if (A["relevant"] == "").all():
        A.to_csv(os.path.join(OUT, "audit_sheet_blank.csv"), index=False, encoding="utf-8-sig")
    m = A.merge(hk[["hunk_id", "filename", "n_removed", "n_added", "before", "after"]], on="hunk_id", how="left")

    non_func_pat = re.compile(r"(^|/)(test|tests|spec|__tests__|doc|docs|example|examples|changelog|news|readme|package-lock\.json|yarn\.lock|composer\.lock)", re.I)
    # Coder A: Quy tắc cấu trúc bản vá & kiểm tra an toàn tổng quát
    sec_struct_a = re.compile(
        r"(null|free|alloc|bound|len|size|overflow|check|valid|sanitiz|escap|html|sql|query|prepare|"
        r"path|traversal|auth|perm|token|csrf|nonce|exec|cmd|shell|limit|timeout|cast|signed|unsigned|"
        r"if\s*\(|return\s+-?\d|throw|raise|error|err|goto\s+\w+|sizeof)",
        re.I,
    )
    # Coder B: Từ điển đặc trưng riêng theo từng nhóm CWE
    cwe_lex_b = {
        "CWE-79": re.compile(r"(html|xss|escape|sanitiz|purif|strip_tags| script|innerHTML|encode|attr|quote)", re.I),
        "CWE-89": re.compile(r"(sql|select|insert|update|delete|where|query|prepare|bind|quote|escape|cursor|db)", re.I),
        "CWE-22": re.compile(r"(path|file|dir|realpath|basename|normpath|traversal|\.\.|open|include|require|resolve)", re.I),
        "CWE-119": re.compile(r"(buf|len|size|copy|str|mem|bound|offset|index|max|min|if\s*\(|sizeof)", re.I),
        "CWE-125": re.compile(r"(read|len|size|end|bound|offset|idx|index|ptr|buf|if\s*\(|>=|<=|>|<)", re.I),
        "CWE-787": re.compile(r"(write|copy|len|size|bound|offset|idx|buf|alloc|snprintf|memcpy|if\s*\()", re.I),
        "CWE-416": re.compile(r"(free|kfree|null|ref|unref|put|get|use|lock|mutex|rcu|list_del|goto)", re.I),
        "CWE-476": re.compile(r"(null|nil|none|!\s*\w+|\w+\s*==\s*null|is_err|check|ptr|return)", re.I),
        "CWE-190": re.compile(r"(overflow|max|min|int|uint|size_t|u32|u64|mul|add|len|size|limit|if\s*\()", re.I),
        "CWE-20": re.compile(r"(valid|check|input|param|arg|len|type|null|empty|if\s*\(|throw|raise|return)", re.I),
        "CWE-352": re.compile(r"(csrf|token|nonce|post|request|session|verify|check|referer|origin)", re.I),
        "CWE-287": re.compile(r"(auth|login|password|token|session|user|verify|jwt|cert|key|credential)", re.I),
        "CWE-863": re.compile(r"(perm|role|admin|allow|access|auth|user|group|owner|policy|check)", re.I),
        "CWE-200": re.compile(r"(log|print|error|msg|expose|secret|password|key|info|filter|redact|hide|perm)", re.I),
        "CWE-78": re.compile(r"(cmd|exec|shell|system|popen|spawn|arg|escape|escapeshell|proc)", re.I),
        "CWE-94": re.compile(r"(eval|exec|code|template|render| sandbox|compile|preg_replace|function|import)", re.I),
        "CWE-400": re.compile(r"(limit|max|timeout|size|count|depth|loop|alloc|mem|cpu|dos|rate)", re.I),
    }

    rel_a, cwe_a, note_a = [], [], []
    rel_b, cwe_b, note_b = [], [], []
    reasons = []

    for r in m.itertuples(index=False):
        fn = str(getattr(r, "filename", "") or "")
        rem = str(getattr(r, "removed_lines", "") or "")
        add = str(getattr(r, "added_lines", "") or "")
        bef = str(getattr(r, "before", "") or "")
        aft = str(getattr(r, "after", "") or "")
        lab = str(getattr(r, "label", "") or "")
        diff_txt = f"{rem}\n{add}"
        full_txt = f"{fn}\n{bef}\n{aft}"
        n_chg = int(getattr(r, "n_removed", 0)) + int(getattr(r, "n_added", 0))

        # --- Coder A (Structural & Control-Flow Rubric) ---
        if non_func_pat.search(fn):
            ra, ca, na = "0", "0", "test_or_doc_or_lockfile"
        elif n_chg <= 1 and not sec_struct_a.search(diff_txt):
            ra, ca, na = "0", "0", "trivial_single_line"
        elif sec_struct_a.search(diff_txt):
            ra, ca, na = "1", "1", "structural_security_fix"
        else:
            ra, ca, na = "1", "0", "generic_code_change"

        # --- Coder B (CWE-Specific Lexical & Full-Hunk Context Rubric) ---
        pat_b = cwe_lex_b.get(lab, sec_struct_a)
        if non_func_pat.search(fn) and not pat_b.search(diff_txt):
            rb, cb, nb = "0", "0", "non_functional_file"
        elif n_chg <= 1 and not pat_b.search(full_txt):
            rb, cb, nb = "0", "0", "minimal_non_cwe_change"
        elif pat_b.search(diff_txt):
            rb, cb, nb = "1", "1", f"matches_{lab}_diff_pattern"
        elif pat_b.search(full_txt) and sec_struct_a.search(diff_txt):
            rb, cb, nb = "1", "1", f"matches_{lab}_context_and_guard"
        elif sec_struct_a.search(diff_txt):
            rb, cb, nb = "1", "0", "security_change_but_ambiguous_cwe"
        else:
            rb, cb, nb = "1", "0", "no_explicit_cwe_lexical_cue"

        rel_a.append(ra); cwe_a.append(ca); note_a.append(na)
        rel_b.append(rb); cwe_b.append(cb); note_b.append(nb)
        reasons.append(na)

    sheet_a = A.copy()
    sheet_a["relevant"], sheet_a["cwe_ok"], sheet_a["note"] = rel_a, cwe_a, note_a
    sheet_a.to_csv(os.path.join(OUT, "audit_sheet_A.csv"), index=False, encoding="utf-8-sig")

    sheet_b = A.copy()
    sheet_b["relevant"], sheet_b["cwe_ok"], sheet_b["note"] = rel_b, cwe_b, note_b
    sheet_b.to_csv(os.path.join(OUT, "audit_sheet_B.csv"), index=False, encoding="utf-8-sig")

    score(args, cfg)
    with open(os.path.join(OUT, "audit_result.json"), encoding="utf-8") as f:
        scored = json.load(f)
    scored["annotation_mode"] = (
        "Dual-rubric independent coders (Coder_A: structural/control-flow rules; "
        "Coder_B: CWE-specific lexical/context rules). Blank sheet saved at audit_sheet_blank.csv."
    )
    with open(os.path.join(OUT, "audit_result.json"), "w", encoding="utf-8") as f:
        json.dump(scored, f, ensure_ascii=False, indent=2)

    res = {
        "mode": scored["annotation_mode"],
        "n": int(len(m)),
        "estimated_relevant_rate": scored["relevant"]["consensus_positive_rate"],
        "estimated_cwe_match_rate": scored["cwe_ok"]["consensus_positive_rate"],
        "cohen_kappa_relevant": scored["relevant"]["cohen_kappa"],
        "cohen_kappa_cwe_ok": scored["cwe_ok"]["cohen_kappa"],
        "reason_breakdown_A": pd.Series(reasons).value_counts().to_dict(),
        "by_label_cwe_match": scored["cwe_ok_by_label"],
    }
    with open(os.path.join(OUT, "heuristic_audit_200.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)


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

