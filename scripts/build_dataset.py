"""Bước 5 – Create reproducible dataset: chạy toàn bộ pipeline theo configs/base.yaml.

    .venv\\Scripts\\python scripts/build_dataset.py                       # DB đầy đủ
    .venv\\Scripts\\python scripts/build_dataset.py --db data/interim/sample.db --out data/interim/sample_out

Đầu ra (trong --out, mặc định data/processed):
    hunks.parquet          mọi hunk + trạng thái lọc + cụm trùng + nhãn + cột split
    file_status.parquet    trạng thái validate từng file_change (phễu coverage)
    summary.json           phễu coverage, duplicate rate, xung đột nhãn, rò rỉ, thời gian từng bước
    MANIFEST_dataset.json  SHA-256 của các file đầu ra (kiểm tra tái lập)
"""
import argparse
import hashlib
import json
import os
import sys
import time

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import pandas as pd  # noqa: E402

from cvefixes_db import connect  # noqa: E402
from dedup import cross_split_duplicates, deduplicate, duplicate_stats  # noqa: E402
from hunks import hunk_filter_reason, parse_diff  # noqa: E402
from metadata import load_candidates  # noqa: E402
from normalize import tokenize  # noqa: E402
from split import leakage_report, make_splits  # noqa: E402
from utils import load_config, save_run_metadata, set_seed  # noqa: E402
from validate import funnel, validate  # noqa: E402

SEP = "<SEP>"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def extract_hunks(files: pd.DataFrame, cfg_h: dict) -> pd.DataFrame:
    keep_cols = ["file_change_id", "hash", "repo_url", "repo_urls", "cve_ids", "cwe_ids", "lang",
                 "filename", "year", "committer_date"]
    rows = []
    for r in files.itertuples(index=False):
        base = {c: getattr(r, c) for c in keep_cols}
        for h in parse_diff(r.diff):
            reason = hunk_filter_reason(h, cfg_h.get("min_changed_lines", 1), cfg_h.get("max_hunk_lines", 200),
                                        cfg_h.get("drop_whitespace_only", True), cfg_h.get("drop_add_only", False))
            d = h.to_dict()
            d["hunk_idx"] = d.pop("idx")
            rows.append({**base, **d, "hunk_id": f"{r.file_change_id}#{h.idx:04d}",
                         "hunk_status": reason or "ok"})
    return pd.DataFrame(rows)


def assign_labels(df: pd.DataFrame, cfg_ds: dict) -> pd.DataFrame:
    nonspec = set(cfg_ds.get("nonspecific_cwe", []))
    policy = cfg_ds.get("multi_cwe_policy", "drop")

    def lab(cwes):
        spec = sorted(c for c in (cwes if isinstance(cwes, (list, tuple)) else list(cwes)) if c not in nonspec)
        if not spec:
            return None, "nonspecific" if len(cwes) else "no_cwe"
        if len(spec) == 1:
            return spec[0], "single"
        return (spec[0], "multi") if policy == "first" else (None, "multi")

    res = [lab(c) for c in df["cwe_ids"]]
    df = df.copy()
    df["label"] = [r[0] for r in res]
    df["label_kind"] = [r[1] for r in res]
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config else load_config()
    seed = args.seed if args.seed is not None else cfg["seeds"][0]
    set_seed(seed)
    db = args.db or cfg["paths"]["db"]
    out = args.out or cfg["paths"]["processed"]
    os.makedirs(out, exist_ok=True)
    timings, summary = {}, {"db": db, "seed": seed}

    t = time.perf_counter()
    con = connect(db)
    files = load_candidates(con)
    timings["metadata_s"] = round(time.perf_counter() - t, 2)
    print(f"[1] metadata: {len(files):,} file_change ứng viên")

    t = time.perf_counter()
    files = validate(files, cfg["validate"], cfg["dataset"]["languages"])
    summary["file_funnel"] = funnel(files)
    timings["validate_s"] = round(time.perf_counter() - t, 2)
    ok_files = files[files["status"] == "ok"]
    print(f"[2] validate: còn {len(ok_files):,} file hợp lệ")

    t = time.perf_counter()
    hunks = extract_hunks(ok_files, cfg["hunks"])
    timings["hunks_s"] = round(time.perf_counter() - t, 2)
    summary["hunk_status"] = hunks["hunk_status"].value_counts().to_dict() if len(hunks) else {}
    summary["hunk_warnings"] = (hunks["warnings"].replace("", pd.NA).dropna().value_counts().to_dict()
                                if len(hunks) else {})
    hk = hunks[hunks["hunk_status"] == "ok"].copy()
    print(f"[3] hunks: {len(hunks):,} hunk, giữ {len(hk):,}")

    t = time.perf_counter()
    nb, na, toks = [], [], []
    for r in hk.itertuples(index=False):
        tb, ta = tokenize(r.before, r.lang), tokenize(r.after, r.lang)
        nb.append(" ".join(tb))
        na.append(" ".join(ta))
        toks.append(tb + [SEP] + ta)
    hk["norm_before"], hk["norm_after"], hk["norm_tokens"] = nb, na, toks
    timings["normalize_s"] = round(time.perf_counter() - t, 2)

    t = time.perf_counter()
    d = cfg["dedup"]
    hk = deduplicate(hk, near_threshold=d["near_jaccard"], num_perm=d["minhash_num_perm"],
                     shingle_size=d["shingle_size"], levels=tuple(d["levels"]))
    timings["dedup_s"] = round(time.perf_counter() - t, 2)
    hk = assign_labels(hk, cfg["dataset"])
    summary["label_kind"] = hk["label_kind"].value_counts().to_dict()
    summary["duplicates"] = duplicate_stats(hk, "label")
    print(f"[4] dedup: {json.dumps({k: v['duplicate_rate'] for k, v in summary['duplicates'].items() if isinstance(v, dict)})}")

    # Split chỉ trên đại diện near-dup có nhãn cụ thể (top-K áp dụng ở bước huấn luyện sau EDA)
    t = time.perf_counter()
    labeled = hk[hk["label"].notna() & hk["is_rep_near"]] if "is_rep_near" in hk else hk[hk["label"].notna()]
    if len(labeled) >= 20 and labeled["label"].nunique() >= 2:
        sp = make_splits(labeled, cfg["split"], seed)
        cols = [c for c in sp.columns if c.startswith("split_")] + ["leak_group"]
        hk = hk.join(sp[cols])
        summary["leakage"] = {c: leakage_report(sp, c) for c in cols if c.startswith("split_")}
        summary["cross_split_duplicates_all_hunks"] = {
            c: cross_split_duplicates(hk.assign(**{c: hk[c].fillna("excluded")}), c, "normalized")
            for c in cols if c.startswith("split_")}
    else:
        summary["leakage"] = "bỏ qua – chưa có đủ nhãn CWE (DB mẫu không có bảng cwe_classification)"
    timings["split_s"] = round(time.perf_counter() - t, 2)
    summary["timings"] = timings

    hk = hk.drop(columns=["norm_tokens"]).sort_values("hunk_id", kind="stable").reset_index(drop=True)
    paths = {"hunks.parquet": hk,
             "file_status.parquet": files.drop(columns=["diff"]).sort_values("file_change_id", kind="stable")}
    manifest = {}
    for name, frame in paths.items():
        p = os.path.join(out, name)
        frame.to_parquet(p, index=False)
        manifest[name] = {"rows": int(len(frame)), "sha256": sha256(p)}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
    with open(os.path.join(out, "MANIFEST_dataset.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    save_run_metadata(os.path.join(out, "run"), cfg, seed, {"db": db, "timings": timings})
    print(f"[5] xong -> {out} | thời gian: {timings}")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
