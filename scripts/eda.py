"""Bước 4 – EDA có căn cứ cho các quyết định trước khi huấn luyện.

Giai đoạn A (cấp file, đọc DB):  chọn ngôn ngữ, ngưỡng tangled commit, privacy trong metadata.
Giai đoạn B (cấp hunk, đọc kết quả build_dataset): top-K CWE, mốc time split, mất cân bằng,
              kích thước hunk, trùng lặp, xung đột nhãn, rò rỉ.

    .venv\\Scripts\\python scripts/eda.py --stage A
    .venv\\Scripts\\python scripts/eda.py --stage B --run data/interim/eda_run2

Đầu ra: results/eda/*.png, results/eda/eda_<stage>.json, results/eda/EDA_<stage>.md
Quy tắc quyết định được viết sẵn trong code (RULES) để không chọn tùy tiện sau khi xem kết quả mô hình.
"""
import argparse
import json
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from cvefixes_db import connect  # noqa: E402
from metadata import load_candidates  # noqa: E402
from normalize import LANG_MAP  # noqa: E402
from utils import load_config  # noqa: E402

OUT = os.path.join("results", "eda")
# Ngôn ngữ đánh dấu/cấu hình – không phải ngôn ngữ lập trình
NON_PROGRAMMING = {"Markdown", "HTML", "CSS", "JSON", "YAML", "XML", "Text", "unknown", "Batchfile", "TeX",
                   "SQL", "Makefile", "Dockerfile", "reStructuredText", "INI", "TOML", "SVG", "Jupyter Notebook"}

RULES = {
    "languages": "Ngôn ngữ LẬP TRÌNH, có grammar tree-sitter, ≥ 1 500 file_change trong CVEfixes",
    "min_files_per_language": 1500,
    "tangled": "Ngưỡng = phân vị 95 của số file MÃ NGUỒN mỗi commit (loại 5% commit lớn nhất)",
    "tangled_quantile": 0.95,
    "top_k": "Giữ CWE có ≥ 500 hunk đại diện (≈ ≥ 100 mẫu/lớp trong test 20%)",
    "min_hunks_per_class": 500,
    "time_cutoff": "Năm nhỏ nhất sao cho phần hunk có nhãn từ năm đó trở đi ≤ 25% và gần 20% nhất",
    "time_test_target": 0.20,
}


def savefig(name):
    os.makedirs(OUT, exist_ok=True)
    p = os.path.join(OUT, name)
    plt.tight_layout()
    plt.savefig(p, dpi=130)
    plt.close()
    return p


def md_table(df, floatfmt="{:.3f}"):
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(floatfmt.format(v) if isinstance(v, float) else f"{v:,}" if isinstance(v, (int, np.integer)) else str(v)
                                       for v in r.values) + " |")
    return "\n".join(lines)


# ------------------------------------------------------------------ giai đoạn A ----
def stage_a(cfg):
    con = connect(cfg["paths"]["db"])
    res, md = {"rules": RULES}, ["# EDA – Giai đoạn A (cấp file)", ""]

    # A1. Ngôn ngữ
    files = load_candidates(con)
    lang = files.groupby("lang").agg(files=("file_change_id", "size"),
                                     commits=("hash", "nunique")).sort_values("files", ascending=False).reset_index()
    lang["programming"] = ~lang["lang"].isin(NON_PROGRAMMING)
    lang["tree_sitter"] = lang["lang"].map(lambda x: x in LANG_MAP)
    lang["selected"] = lang.programming & lang.tree_sitter & (lang.files >= RULES["min_files_per_language"])
    chosen = lang.loc[lang.selected, "lang"].tolist()
    res["languages_table"] = lang.head(25).to_dict("records")
    res["languages_selected"] = chosen
    top = lang.head(20)
    plt.figure(figsize=(9, 4.5))
    plt.bar(top["lang"], top["files"], color=["tab:green" if s else "tab:gray" for s in top["selected"]])
    plt.axhline(RULES["min_files_per_language"], ls="--", c="r", lw=1)
    plt.xticks(rotation=60, ha="right"); plt.ylabel("Số file_change"); plt.title("Ngôn ngữ (xanh = được chọn)")
    savefig("A1_languages.png")
    md += ["## A1. Chọn ngôn ngữ", f"Quy tắc: {RULES['languages']}.", "", md_table(lang.head(20)), "",
           f"**Chọn:** {', '.join(chosen)}", "", "![](A1_languages.png)", ""]

    # A2. Tangled commit – đếm file MÃ NGUỒN (theo ngôn ngữ đã chọn) mỗi commit
    files = load_candidates(con, code_languages=chosen)
    sel = files[files["lang"].isin(chosen) & ~files["change_type"].astype(str).str.endswith(("ADD", "DELETE"))]
    per_commit = files.groupby("hash")["n_code_files_in_commit"].first()
    per_commit = per_commit[per_commit > 0]
    q = float(per_commit.quantile(RULES["tangled_quantile"]))
    thr = int(np.ceil(q))
    grid = [1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 100, 10 ** 9]
    curve = [{"max_code_files": (g if g < 10 ** 9 else "∞"),
              "files_kept": int((sel["n_code_files_in_commit"] <= g).sum()),
              "pct_files_kept": round(float((sel["n_code_files_in_commit"] <= g).mean()), 4),
              "pct_commits_kept": round(float((per_commit <= g).mean()), 4)} for g in grid]
    res["tangled"] = {"quantiles_code_files_per_commit": {f"p{int(p * 100)}": float(per_commit.quantile(p))
                                                          for p in (0.5, 0.75, 0.9, 0.95, 0.99)},
                      "chosen_threshold": thr, "curve": curve,
                      "old_rule_all_files_gt10_removed_files": int((sel["n_files_in_commit"] > 10).sum()),
                      "new_rule_removed_files": int((sel["n_code_files_in_commit"] > thr).sum()),
                      "candidate_files": int(len(sel))}
    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].hist(np.clip(per_commit, 0, 60), bins=60, color="tab:blue")
    ax[0].axvline(thr, c="r", ls="--", label=f"ngưỡng p95 = {thr}")
    ax[0].set_yscale("log"); ax[0].set_xlabel("Số file mã nguồn / commit (cắt ở 60)"); ax[0].legend()
    xs = [c["max_code_files"] for c in curve[:-1]]
    ax[1].plot(range(len(xs)), [c["pct_files_kept"] for c in curve[:-1]], "o-", label="% file giữ lại")
    ax[1].plot(range(len(xs)), [c["pct_commits_kept"] for c in curve[:-1]], "s-", label="% commit giữ lại")
    ax[1].set_xticks(range(len(xs))); ax[1].set_xticklabels(xs); ax[1].set_xlabel("Ngưỡng tối đa"); ax[1].legend()
    savefig("A2_tangled.png")
    md += ["## A2. Ngưỡng tangled commit", f"Quy tắc: {RULES['tangled']}.", "",
           f"Phân vị số file mã nguồn/commit: {res['tangled']['quantiles_code_files_per_commit']}", "",
           md_table(pd.DataFrame(curve)), "",
           f"**Chọn ngưỡng = {thr} file mã nguồn.** Quy tắc cũ (>10 file bất kỳ) loại "
           f"{res['tangled']['old_rule_all_files_gt10_removed_files']:,} / {len(sel):,} file ứng viên; "
           f"quy tắc mới loại {res['tangled']['new_rule_removed_files']:,}.", "", "![](A2_tangled.png)", ""]

    # A3. Privacy trong metadata
    email = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}"
    pii = {
        "commits_with_author": con.execute("SELECT COUNT(*) FROM commits WHERE author IS NOT NULL AND author<>''").fetchone()[0],
        "commits_with_committer": con.execute("SELECT COUNT(*) FROM commits WHERE committer IS NOT NULL AND committer<>''").fetchone()[0],
        "commit_msgs_with_email": sum(1 for (m,) in con.execute("SELECT msg FROM commits") if m and re.search(email, m)),
        "n_commits": con.execute("SELECT COUNT(*) FROM commits").fetchone()[0],
    }
    res["privacy_metadata"] = pii
    md += ["## A3. Dữ liệu cá nhân trong metadata", "",
           f"- Commit có tên tác giả: {pii['commits_with_author']:,}/{pii['n_commits']:,}; có tên committer: {pii['commits_with_committer']:,}",
           f"- Commit message chứa email: {pii['commit_msgs_with_email']:,}",
           "- **Quyết định:** dữ liệu dẫn xuất KHÔNG chứa cột author/committer/msg; email trong mã nguồn được thay bằng `<EMAIL>`.", ""]
    return res, md


# ------------------------------------------------------------------ giai đoạn B ----
def stage_b(cfg, run_dir):
    hk = pd.read_parquet(os.path.join(run_dir, "hunks.parquet"))
    summary = json.load(open(os.path.join(run_dir, "summary.json"), encoding="utf-8"))
    res, md = {"rules": RULES, "run": run_dir}, ["# EDA – Giai đoạn B (cấp hunk)", ""]
    reps = hk[hk["is_rep_near"]]
    lab = reps[reps["label"].notna()]

    # B1. Top-K CWE
    vc = lab["label"].value_counts()
    k = int((vc >= RULES["min_hunks_per_class"]).sum())
    topk = vc.head(k)
    cum = (vc.cumsum() / vc.sum()).values
    res["topk"] = {"chosen_k": k, "classes": topk.to_dict(), "coverage_of_labeled": round(float(topk.sum() / len(lab)), 4),
                   "n_labeled_reps": int(len(lab)), "n_distinct_cwe": int(vc.size),
                   "coverage_k10": round(float(cum[min(9, len(cum) - 1)]), 4),
                   "coverage_k20": round(float(cum[min(19, len(cum) - 1)]), 4)}
    imb = topk.max() / topk.min()
    p = topk / topk.sum()
    res["imbalance"] = {"ratio_max_min": round(float(imb), 2),
                        "normalized_entropy": round(float(-(p * np.log(p)).sum() / np.log(len(p))), 4),
                        "majority_class_share": round(float(p.max()), 4)}
    fig, ax = plt.subplots(1, 2, figsize=(12, 4.2))
    v30 = vc.head(30)
    ax[0].bar(v30.index, v30.values, color=["tab:green" if i < k else "tab:gray" for i in range(len(v30))])
    ax[0].axhline(RULES["min_hunks_per_class"], c="r", ls="--", lw=1)
    ax[0].set_yscale("log"); ax[0].tick_params(axis="x", rotation=75); ax[0].set_title("Top-30 CWE (số hunk đại diện)")
    ax[1].plot(np.arange(1, len(cum) + 1), cum)
    ax[1].axvline(k, c="r", ls="--", label=f"K = {k}"); ax[1].set_xscale("log")
    ax[1].set_xlabel("K"); ax[1].set_ylabel("Tỷ lệ dữ liệu phủ"); ax[1].legend()
    savefig("B1_cwe_topk.png")
    md += ["## B1. Top-K CWE & mất cân bằng lớp", f"Quy tắc: {RULES['top_k']}.", "",
           f"- Hunk đại diện có nhãn cụ thể: {len(lab):,}; số CWE: {vc.size}",
           f"- Top-10 phủ {res['topk']['coverage_k10']:.1%}, top-20 phủ {res['topk']['coverage_k20']:.1%}",
           f"- **Chọn K = {k}**, phủ {res['topk']['coverage_of_labeled']:.1%} dữ liệu có nhãn; lớp còn lại bị loại (không gộp 'Other' vì không đồng nhất)",
           f"- Mất cân bằng trong top-K: max/min = {imb:.2f}, entropy chuẩn hóa = {res['imbalance']['normalized_entropy']}, lớp lớn nhất chiếm {p.max():.1%}",
           "- **Biện pháp:** class_weight='balanced'; metric chính Macro-F1; báo cáo per-class P/R; không oversampling.", "",
           md_table(topk.rename_axis("CWE").reset_index(name="hunks")), "", "![](B1_cwe_topk.png)", ""]

    # B2. Mốc time split
    yr = pd.to_numeric(lab[lab["label"].isin(topk.index)]["year"], errors="coerce")
    by_year = yr.value_counts().sort_index()
    tail = by_year[::-1].cumsum()[::-1] / by_year.sum()
    cands = tail[tail <= 0.25]
    cutoff = int((cands - RULES["time_test_target"]).abs().idxmin()) if len(cands) else int(by_year.index.max())
    res["time"] = {"by_year": {int(a): int(b) for a, b in by_year.items()}, "chosen_cutoff": cutoff,
                   "test_share": round(float(tail.loc[cutoff]), 4)}
    plt.figure(figsize=(9, 3.8))
    plt.bar(by_year.index.astype(int), by_year.values, color=["tab:orange" if y >= cutoff else "tab:blue" for y in by_year.index])
    plt.title(f"Hunk top-K theo năm commit (cam = test, cutoff {cutoff})"); savefig("B2_time.png")
    md += ["## B2. Mốc time split", f"Quy tắc: {RULES['time_cutoff']}.", "",
           f"**Chọn cutoff = {cutoff}** → test chiếm {tail.loc[cutoff]:.1%} hunk top-K.", "", "![](B2_time.png)", ""]

    # B3. Kích thước hunk
    size = (hk["n_context"] + hk["n_removed"] + hk["n_added"])
    res["hunk_size"] = {f"p{q}": float(size.quantile(q / 100)) for q in (50, 90, 99)}
    res["hunk_kind"] = {"add_only": int((hk.n_removed == 0).sum()), "delete_only": int((hk.n_added == 0).sum()),
                        "both": int(((hk.n_removed > 0) & (hk.n_added > 0)).sum())}
    plt.figure(figsize=(7, 3.5)); plt.hist(np.clip(size, 0, 120), bins=60); plt.yscale("log")
    plt.xlabel("Số dòng / hunk (cắt ở 120)"); savefig("B3_hunk_size.png")
    md += ["## B3. Kích thước hunk", "", f"- Phân vị số dòng: {res['hunk_size']}",
           f"- Chỉ thêm dòng: {res['hunk_kind']['add_only']:,} · chỉ xóa: {res['hunk_kind']['delete_only']:,} · cả hai: {res['hunk_kind']['both']:,}",
           "", "![](B3_hunk_size.png)", ""]

    # B4. Trùng lặp & xung đột nhãn
    d = summary["duplicates"]
    res["duplicates"] = d
    lv = ["exact", "normalized", "near"]
    plt.figure(figsize=(6, 3.5)); plt.bar(lv, [d[x]["duplicate_rate"] for x in lv], color="tab:purple")
    for i, x in enumerate(lv):
        plt.text(i, d[x]["duplicate_rate"], f"{d[x]['duplicate_rate']:.1%}", ha="center", va="bottom")
    plt.title("Duplicate rate theo mức"); savefig("B4_duplicates.png")
    md += ["## B4. Trùng lặp & chất lượng nhãn", "",
           md_table(pd.DataFrame([{"mức": x, **{k2: v for k2, v in d[x].items()}} for x in lv])), "",
           f"- Nhãn: {summary.get('label_kind')}", "", "![](B4_duplicates.png)", ""]

    # B5. Rò rỉ
    leak = summary.get("leakage", {})
    res["leakage"] = leak
    if isinstance(leak, dict):
        rows = [{"split": s, **{k2: v for k2, v in r.items()}} for s, r in leak.items()]
        md += ["## B5. Rò rỉ train–test theo chiến lược chia", "", md_table(pd.DataFrame(rows)), ""]
    res["privacy_hunks"] = summary.get("privacy")
    md += ["## B6. Privacy trong hunk", "", f"- {summary.get('privacy')}", ""]
    return res, md


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["A", "B"], required=True)
    ap.add_argument("--run", default=os.path.join("data", "interim", "eda_run2"))
    args = ap.parse_args()
    cfg = load_config()
    res, md = stage_a(cfg) if args.stage == "A" else stage_b(cfg, args.run)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"eda_{args.stage}.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2, default=str)
    with open(os.path.join(OUT, f"EDA_{args.stage}.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k not in ("languages_table", "rules")}, ensure_ascii=False,
                     indent=1, default=str)[:4000])


if __name__ == "__main__":
    main()
