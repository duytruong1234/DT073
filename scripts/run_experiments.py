"""Bước 6 – Chạy toàn bộ ma trận thí nghiệm có kiểm soát (E0..E7 × 3 seed = 24 lần chạy)
theo đúng đăng ký trước trong PREREGISTRATION.md §3, §5, §6.

    .venv\\Scripts\\python scripts/run_experiments.py

Đầu ra:
  * results/experiments/<Exp>/seed_<seed>/metrics.json
  * results/experiments/<Exp>/seed_<seed>/predictions.csv
  * results/experiments/<Exp>/seed_<seed>/run_meta.json
  * results/models/E5_seed42.joblib (phục vụ demo Bước 8)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tracemalloc

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import psutil  # noqa: E402

from features import build_corpus  # noqa: E402
from models import (  # noqa: E402
    compute_metrics,
    fit_dummy,
    fit_tuned_e6,
    fit_tuned_logreg,
    make_vectorizer,
    predict_scores,
)
from utils import load_config, save_run_metadata, set_seed  # noqa: E402

EXPERIMENTS = {
    "E0": {
        "dedup": True,
        "split": "split_project",
        "feature": "none",
        "model": "dummy",
        "role": "Mức sàn (Dummy majority & stratified)",
    },
    "E1": {
        "dedup": False,
        "split": "split_random_nodedup",
        "feature": "before",
        "model": "logreg",
        "role": "Đo hiệu ứng trùng lặp + rò rỉ (không dedup, random split)",
    },
    "E2": {
        "dedup": True,
        "split": "split_random",
        "feature": "before",
        "model": "logreg",
        "role": "Đo rò rỉ (dedup, random split) - RQ4",
    },
    "E3": {
        "dedup": True,
        "split": "split_project",
        "feature": "before",
        "model": "logreg",
        "role": "BASELINE chính (dedup, project split, before)",
    },
    "E4": {
        "dedup": True,
        "split": "split_project",
        "feature": "patch",
        "model": "logreg",
        "role": "Ablation: thông tin bản vá (before + after + DEL/ADD)",
    },
    "E5": {
        "dedup": True,
        "split": "split_project",
        "feature": "patch_norm",
        "model": "logreg",
        "role": "BIẾN THỂ chính (E4 + chuẩn hóa tree-sitter)",
    },
    "E6": {
        "dedup": True,
        "split": "split_project",
        "feature": "patch_norm",
        "model": "e6",
        "role": "Biến thể mô hình (LinearSVC / LightGBM trên E5)",
    },
    "E7": {
        "dedup": True,
        "split": "split_time",
        "feature": "patch_norm",
        "model": "logreg",
        "role": "Tổng quát hóa theo thời gian (cutoff 2023)",
    },
}


def _top3_strings(y_prob: np.ndarray | None, classes: list[str]) -> list[str]:
    if y_prob is None or len(classes) == 0:
        return [""] * (0 if y_prob is None else len(y_prob))
    k = min(3, len(classes))
    idx = np.argsort(-y_prob, axis=1)[:, :k]
    return ["|".join(classes[j] for j in row) for row in idx]


def _top3_hit(y_true: np.ndarray, top3_strs: list[str]) -> list[bool]:
    return [yt in s.split("|") for yt, s in zip(y_true, top3_strs)]


def run_single(
    exp_id: str,
    exp_cfg: dict,
    seed: int,
    df_sub: pd.DataFrame,
    text_cache: dict[str, pd.Series],
    out_dir: str,
    full_cfg: dict,
    run_lgbm_in_e6: bool = True,
) -> dict:
    set_seed(seed)
    proc = psutil.Process(os.getpid())
    rss_start = proc.memory_info().rss / (1024 * 1024)
    t0 = time.perf_counter()

    split_col = exp_cfg["split"]
    df_tr = df_sub[df_sub[split_col] == "train"].sort_values("hunk_id", kind="stable")
    df_va = df_sub[df_sub[split_col] == "val"].sort_values("hunk_id", kind="stable")
    df_te = df_sub[df_sub[split_col] == "test"].sort_values("hunk_id", kind="stable")

    # Kiểm tra bất biến không chồng lấn mẫu giữa train/val/test
    s_tr, s_va, s_te = set(df_tr["hunk_id"]), set(df_va["hunk_id"]), set(df_te["hunk_id"])
    assert s_tr.isdisjoint(s_va) and s_tr.isdisjoint(s_te) and s_va.isdisjoint(s_te), "Train/val/test overlap!"

    y_tr = df_tr["label"].to_numpy()
    y_va = df_va["label"].to_numpy()
    y_te = df_te["label"].to_numpy()

    os.makedirs(out_dir, exist_ok=True)
    fmode = exp_cfg["feature"]
    mtype = exp_cfg["model"]

    if mtype == "dummy":
        t_tr0 = time.perf_counter()
        dum = fit_dummy(y_tr, len(y_va), len(y_te), seed=seed)
        train_s = time.perf_counter() - t_tr0
        t_inf0 = time.perf_counter()
        va_pred_m, va_prob_m, te_pred_m, te_prob_m, cls_m = dum["majority"]
        va_pred_s, va_prob_s, te_pred_s, te_prob_s, cls_s = dum["stratified"]
        infer_s = time.perf_counter() - t_inf0

        m_val_maj = compute_metrics(y_va, va_pred_m, va_prob_m, cls_m)
        m_test_maj = compute_metrics(y_te, te_pred_m, te_prob_m, cls_m)
        m_val_str = compute_metrics(y_va, va_pred_s, va_prob_s, cls_s)
        m_test_str = compute_metrics(y_te, te_pred_s, te_prob_s, cls_s)

        primary_test = m_test_str if m_test_str["macro_f1"] >= m_test_maj["macro_f1"] else m_test_maj
        primary_val = m_val_str if m_test_str["macro_f1"] >= m_test_maj["macro_f1"] else m_val_maj
        tuning = {
            "strategies": ["most_frequent", "stratified"],
            "majority_val_macro_f1": m_val_maj["macro_f1"],
            "stratified_val_macro_f1": m_val_str["macro_f1"],
        }
        vocab_size = 0
        top3_s = _top3_strings(te_prob_s, cls_s)
        pred_df = pd.DataFrame({
            "hunk_id": df_te["hunk_id"].to_numpy(),
            "y_true": y_te,
            "y_pred": te_pred_s,
            "y_pred_majority": te_pred_m,
            "y_pred_stratified": te_pred_s,
            "top3_preds": top3_s,
            "correct": (te_pred_s == y_te),
            "correct_majority": (te_pred_m == y_te),
            "top3_correct": _top3_hit(y_te, top3_s),
        })
        sub_models = {
            "majority": {"val": m_val_maj, "test": m_test_maj},
            "stratified": {"val": m_val_str, "test": m_test_str},
        }
        rss_peak = proc.memory_info().rss / (1024 * 1024)
    else:
        tr_texts = text_cache[fmode].loc[df_tr["hunk_id"]].tolist()
        va_texts = text_cache[fmode].loc[df_va["hunk_id"]].tolist()
        te_texts = text_cache[fmode].loc[df_te["hunk_id"]].tolist()

        t_tr0 = time.perf_counter()
        vec = make_vectorizer()
        X_tr = vec.fit_transform(tr_texts)
        X_va = vec.transform(va_texts)
        vocab_size = len(vec.vocabulary_)

        if mtype == "logreg":
            clf, tuning = fit_tuned_logreg(X_tr, y_tr, X_va, y_va, seed=seed)
        elif mtype == "e6":
            clf, tuning = fit_tuned_e6(X_tr, y_tr, X_va, y_va, seed=seed, run_lgbm=run_lgbm_in_e6)
        else:
            raise ValueError(f"Unknown model type: {mtype}")
        train_s = time.perf_counter() - t_tr0
        rss_mid = proc.memory_info().rss / (1024 * 1024)

        va_pred, va_prob, classes = predict_scores(clf, X_va)
        primary_val = compute_metrics(y_va, va_pred, va_prob, classes)

        # Đánh giá tập test ĐÚNG 1 LẦN sau khi đã chốt mô hình trên val
        t_inf0 = time.perf_counter()
        X_te = vec.transform(te_texts)
        te_pred, te_prob, classes = predict_scores(clf, X_te)
        infer_s = time.perf_counter() - t_inf0
        rss_peak = max(rss_start, rss_mid, proc.memory_info().rss / (1024 * 1024))

        primary_test = compute_metrics(y_te, te_pred, te_prob, classes)
        top3_s = _top3_strings(te_prob, classes)
        pred_df = pd.DataFrame({
            "hunk_id": df_te["hunk_id"].to_numpy(),
            "y_true": y_te,
            "y_pred": te_pred,
            "top3_preds": top3_s,
            "correct": (te_pred == y_te),
            "top3_correct": _top3_hit(y_te, top3_s),
        })
        sub_models = None

        if exp_id == "E5" and seed == 42:
            model_dir = os.path.join(full_cfg["paths"]["results"], "models")
            os.makedirs(model_dir, exist_ok=True)
            joblib.dump(
                {"vectorizer": vec, "classifier": clf, "feature_mode": fmode, "seed": seed, "classes": classes},
                os.path.join(model_dir, "E5_seed42.joblib"),
            )

    total_s = time.perf_counter() - t0
    cost = {
        "train_s": round(train_s, 3),
        "infer_s": round(infer_s, 3),
        "total_s": round(total_s, 3),
        "peak_rss_mb": round(rss_peak, 2),
        "rss_delta_mb": round(max(0.0, rss_peak - rss_start), 2),
    }

    payload = {
        "exp": exp_id,
        "seed": seed,
        "role": exp_cfg["role"],
        "spec": exp_cfg,
        "n_train": int(len(df_tr)),
        "n_val": int(len(df_va)),
        "n_test": int(len(df_te)),
        "vocab_size": int(vocab_size),
        "tuning": tuning,
        "val": primary_val,
        "test": primary_test,
        "sub_models": sub_models,
        "cost": cost,
    }

    with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    pred_df.to_csv(os.path.join(out_dir, "predictions.csv"), index=False, encoding="utf-8")
    save_run_metadata(os.path.join(out_dir, "run"), full_cfg, seed, {"exp": exp_id, "cost": cost})
    return payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--processed", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--exps", nargs="*", default=None, help="Chỉ chạy một số Exp (mặc định: E0..E7)")
    ap.add_argument("--seeds", nargs="*", type=int, default=None)
    ap.add_argument("--skip-lgbm", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config else load_config()
    proc_dir = args.processed or cfg["paths"]["processed"]
    out_root = args.out or os.path.join(cfg["paths"]["results"], "experiments")
    seeds = args.seeds or cfg["seeds"]
    exp_list = args.exps or list(EXPERIMENTS.keys())

    hunks = pd.read_parquet(os.path.join(proc_dir, "hunks.parquet"))
    splits = pd.read_parquet(os.path.join(proc_dir, "splits.parquet"))

    topk_df = hunks[hunks["in_topk"]].copy().sort_values("hunk_id", kind="stable")
    print(f"[Init] Tiền tính chuỗi đặc trưng cho {len(topk_df):,} hunk top-K...")
    t_feat = time.perf_counter()
    text_cache: dict[str, pd.Series] = {}
    needed_modes = {EXPERIMENTS[e]["feature"] for e in exp_list if EXPERIMENTS[e]["feature"] != "none"}
    for mode in sorted(needed_modes):
        t_m = time.perf_counter()
        text_cache[mode] = pd.Series(build_corpus(topk_df, mode=mode), index=topk_df["hunk_id"])
        print(f"  - mode={mode:<10}: {time.perf_counter() - t_m:.2f}s")
    print(f"[Init] Xong trích đặc trưng ({time.perf_counter() - t_feat:.2f}s)")

    all_runs = []
    for exp_id in exp_list:
        exp_cfg = EXPERIMENTS[exp_id]
        for seed in seeds:
            sp_seed = splits[splits["seed"] == seed]
            merged = topk_df.merge(sp_seed, on="hunk_id", how="inner")
            if exp_cfg["dedup"]:
                merged = merged[merged["is_rep_near"]].copy()
            out_dir = os.path.join(out_root, exp_id, f"seed_{seed}")
            res = run_single(
                exp_id=exp_id,
                exp_cfg=exp_cfg,
                seed=seed,
                df_sub=merged,
                text_cache=text_cache,
                out_dir=out_dir,
                full_cfg=cfg,
                run_lgbm_in_e6=not args.skip_lgbm,
            )
            te = res["test"]
            print(
                f"[{exp_id} | seed={seed:<4}] val_F1={res['val']['macro_f1']:.4f} | "
                f"test_MacroF1={te['macro_f1']:.4f} | WF1={te['weighted_f1']:.4f} | "
                f"MCC={te['mcc']:.4f} | Top3={te['top3_accuracy'] or 0:.4f} | "
                f"train={res['cost']['train_s']:.2f}s"
            )
            all_runs.append({
                "exp": exp_id,
                "seed": seed,
                "role": exp_cfg["role"],
                "split": exp_cfg["split"],
                "feature": exp_cfg["feature"],
                "model": exp_cfg["model"],
                "n_train": res["n_train"],
                "n_val": res["n_val"],
                "n_test": res["n_test"],
                "vocab_size": res["vocab_size"],
                "val_macro_f1": res["val"]["macro_f1"],
                "test_macro_f1": te["macro_f1"],
                "test_weighted_f1": te["weighted_f1"],
                "test_mcc": te["mcc"],
                "test_accuracy": te["accuracy"],
                "test_top3_accuracy": te["top3_accuracy"],
                "train_s": res["cost"]["train_s"],
                "infer_s": res["cost"]["infer_s"],
                "peak_rss_mb": res["cost"]["peak_rss_mb"],
            })

    os.makedirs(out_root, exist_ok=True)
    pd.DataFrame(all_runs).to_csv(os.path.join(out_root, "runs_summary.csv"), index=False, encoding="utf-8")
    print(f"[Done] Đã lưu {len(all_runs)} lần chạy vào {out_root}")


if __name__ == "__main__":
    main()
