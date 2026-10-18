"""Bước 7 – Tổng hợp đánh giá toàn diện (M0..M6):
  * Bootstrap CI 95% (1 000 lần) cho mọi (Exp, seed)
  * Mean ± std qua 3 seed + kiểm tra độ ổn định (M3: std <= 0.02)
  * Paired bootstrap ΔMacro-F1 + kiểm định McNemar cho M1 (E3 vs E0), M2 (E5 vs E3), Ablation (E4 vs E3, E5 vs E4, E6 vs E5)
  * Independent bootstrap ΔMacro-F1 cho M5 / RQ4 (E2 vs E3) và RQ2 (E1 vs E2)
  * Biểu đồ ma trận nhầm lẫn (E3, E5) + phân tích cặp CWE cha-con + 50 mẫu lỗi của E5 (seed 42) (M6)
"""
from __future__ import annotations

import argparse
import json
import os
import random
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
import seaborn as sns  # noqa: E402

from evaluate import (  # noqa: E402
    bootstrap_ci,
    classify_error_reason,
    independent_bootstrap_delta,
    mcnemar_test,
    paired_bootstrap_delta,
    same_cwe_family,
)
from utils import load_config  # noqa: E402


def _plot_cm(cm: np.ndarray, labels: list[str], title: str, out_path: str) -> None:
    row_sums = cm.sum(axis=1, keepdims=True)
    cm_norm = np.divide(cm, row_sums, out=np.zeros_like(cm, dtype=float), where=row_sums > 0)
    fig, ax = plt.subplots(figsize=(12, 10), dpi=150)
    sns.heatmap(
        cm_norm,
        xticklabels=labels,
        yticklabels=labels,
        cmap="Blues",
        annot=True,
        fmt=".2f",
        cbar_kws={"label": "Recall theo hàng (chuẩn hóa)"},
        ax=ax,
        annot_kws={"size": 7},
    )
    ax.set_xlabel("Dự đoán (Predicted CWE)")
    ax.set_ylabel("Nhãn thực (True CWE)")
    ax.set_title(title)
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--exp-dir", default=os.path.join("results", "experiments"))
    ap.add_argument("--out", default=os.path.join("results", "evaluation"))
    ap.add_argument("--n-boot", type=int, default=1000)
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config else load_config()
    seeds = cfg["seeds"]
    classes = cfg["dataset"]["top_k_cwe"]
    os.makedirs(args.out, exist_ok=True)

    exps = ["E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"]
    metrics_data: dict[tuple[str, int], dict] = {}
    preds_data: dict[tuple[str, int], pd.DataFrame] = {}

    for e in exps:
        for s in seeds:
            mdir = os.path.join(args.exp_dir, e, f"seed_{s}")
            with open(os.path.join(mdir, "metrics.json"), encoding="utf-8") as f:
                metrics_data[(e, s)] = json.load(f)
            preds_data[(e, s)] = pd.read_csv(os.path.join(mdir, "predictions.csv")).sort_values("hunk_id", kind="stable")

    # 1. Bootstrap 95% CI cho từng (Exp, seed)
    print(f"[1] Tính Bootstrap CI 95% ({args.n_boot} lần) cho mọi (Exp, seed)...")
    per_run_rows = []
    boot_cache: dict[tuple[str, int], dict] = {}

    for e in exps:
        for s in seeds:
            m = metrics_data[(e, s)]
            pdf = preds_data[(e, s)]
            bci = bootstrap_ci(pdf["y_true"].to_numpy(), pdf["y_pred"].to_numpy(), classes=classes, n_boot=args.n_boot, seed=s)
            boot_cache[(e, s)] = bci
            te = m["test"]
            per_run_rows.append({
                "exp": e,
                "seed": s,
                "role": m["role"],
                "n_train": m["n_train"],
                "n_val": m["n_val"],
                "n_test": m["n_test"],
                "val_macro_f1": m["val"]["macro_f1"],
                "test_macro_f1": te["macro_f1"],
                "macro_f1_ci95_low": bci["macro_f1"]["ci95_low"],
                "macro_f1_ci95_high": bci["macro_f1"]["ci95_high"],
                "test_weighted_f1": te["weighted_f1"],
                "weighted_f1_ci95_low": bci["weighted_f1"]["ci95_low"],
                "weighted_f1_ci95_high": bci["weighted_f1"]["ci95_high"],
                "test_mcc": te["mcc"],
                "mcc_ci95_low": bci["mcc"]["ci95_low"],
                "mcc_ci95_high": bci["mcc"]["ci95_high"],
                "test_accuracy": te["accuracy"],
                "test_top3_accuracy": te["top3_accuracy"],
                "train_s": m["cost"]["train_s"],
                "infer_s": m["cost"]["infer_s"],
                "peak_rss_mb": m["cost"]["peak_rss_mb"],
            })
            if e == "E0":
                bci_maj = bootstrap_ci(
                    pdf["y_true"].to_numpy(), pdf["y_pred_majority"].to_numpy(), classes=classes, n_boot=args.n_boot, seed=s
                )
                boot_cache[("E0_majority", s)] = bci_maj

    df_runs = pd.DataFrame(per_run_rows)
    df_runs.to_csv(os.path.join(args.out, "per_seed_results_with_ci.csv"), index=False, encoding="utf-8")

    # 2. Tổng hợp Mean ± Std qua 3 seed (M3)
    agg_rows = []
    for e in exps:
        sub = df_runs[df_runs["exp"] == e]
        mf1_mean, mf1_std = float(sub["test_macro_f1"].mean()), float(sub["test_macro_f1"].std(ddof=1))
        wf1_mean, wf1_std = float(sub["test_weighted_f1"].mean()), float(sub["test_weighted_f1"].std(ddof=1))
        mcc_mean, mcc_std = float(sub["test_mcc"].mean()), float(sub["test_mcc"].std(ddof=1))
        acc_mean, acc_std = float(sub["test_accuracy"].mean()), float(sub["test_accuracy"].std(ddof=1))
        t3_mean, t3_std = float(sub["test_top3_accuracy"].mean()), float(sub["test_top3_accuracy"].std(ddof=1))
        agg_rows.append({
            "exp": e,
            "role": sub["role"].iloc[0],
            "macro_f1_mean": round(mf1_mean, 4),
            "macro_f1_std": round(mf1_std, 4),
            "macro_f1_str": f"{mf1_mean:.4f} ± {mf1_std:.4f}",
            "weighted_f1_mean": round(wf1_mean, 4),
            "weighted_f1_std": round(wf1_std, 4),
            "weighted_f1_str": f"{wf1_mean:.4f} ± {wf1_std:.4f}",
            "mcc_mean": round(mcc_mean, 4),
            "mcc_std": round(mcc_std, 4),
            "mcc_str": f"{mcc_mean:.4f} ± {mcc_std:.4f}",
            "top3_acc_mean": round(t3_mean, 4),
            "top3_acc_std": round(t3_std, 4),
            "top3_acc_str": f"{t3_mean:.4f} ± {t3_std:.4f}",
            "accuracy_mean": round(acc_mean, 4),
            "accuracy_std": round(acc_std, 4),
            "stable_m3": bool(mf1_std <= 0.02),
            "mean_train_s": round(float(sub["train_s"].mean()), 2),
            "mean_infer_s": round(float(sub["infer_s"].mean()), 3),
            "max_rss_mb": round(float(sub["peak_rss_mb"].max()), 1),
        })
    df_agg = pd.DataFrame(agg_rows)
    df_agg.to_csv(os.path.join(args.out, "table_main_results.csv"), index=False, encoding="utf-8")

    # 3. Kiểm định thống kê: Paired Bootstrap & McNemar (M1, M2, Ablation) + Independent Bootstrap (M5/RQ4, RQ2)
    print("[2] Chạy kiểm định Paired Bootstrap & McNemar cho M1, M2, M5 và Ablation...")
    paired_pairs = [
        ("E0_stratified", "E3", "M1: Baseline (E3) vs Dummy stratified (E0)"),
        ("E0_majority", "E3", "M1: Baseline (E3) vs Dummy majority (E0)"),
        ("E3", "E4", "Ablation 1: Patch info (E4) vs Before-only Baseline (E3)"),
        ("E4", "E5", "Ablation 2: Tree-sitter norm (E5) vs Raw patch (E4)"),
        ("E3", "E5", "M2 (RQ5): Main Variant (E5) vs Main Baseline (E3)"),
        ("E5", "E6", "Model Ablation: LinearSVC/LGBM (E6) vs LogReg (E5)"),
        ("E3", "E6", "Variant Model (E6) vs Main Baseline (E3)"),
    ]
    test_rows = []
    for exp_a, exp_b, desc in paired_pairs:
        for s in seeds:
            df_b = preds_data[(exp_b, s)]
            if exp_a == "E0_majority":
                df_a = preds_data[("E0", s)]
                pa = df_a["y_pred_majority"].to_numpy()
            elif exp_a == "E0_stratified":
                df_a = preds_data[("E0", s)]
                pa = df_a["y_pred_stratified"].to_numpy()
            else:
                df_a = preds_data[(exp_a, s)]
                pa = df_a["y_pred"].to_numpy()
            assert (df_a["hunk_id"].to_numpy() == df_b["hunk_id"].to_numpy()).all()
            yt = df_b["y_true"].to_numpy()
            pb = df_b["y_pred"].to_numpy()

            pboot = paired_bootstrap_delta(yt, pa, pb, classes=classes, n_boot=args.n_boot, seed=s)
            mcn = mcnemar_test(yt, pa, pb)
            test_rows.append({
                "comparison": f"{exp_b} vs {exp_a}",
                "description": desc,
                "type": "paired_same_test_set",
                "seed": s,
                **pboot,
                **mcn,
            })

    # Independent bootstrap cho RQ4 (E2 random vs E3 project) và RQ2 (E1 no-dedup random vs E2 dedup random)
    indep_pairs = [
        ("E3", "E2", "M5 (RQ4): Random split (E2) vs Project split (E3) - Leakage inflation"),
        ("E2", "E1", "RQ2: No-dedup random (E1) vs Dedup random (E2) - Duplicate inflation"),
        ("E3", "E1", "Combined: No-dedup random (E1) vs Dedup project (E3)"),
        ("E5", "E7", "Temporal: Time split 2023+ (E7) vs Project split (E5)"),
    ]
    for exp_a, exp_b, desc in indep_pairs:
        for s in seeds:
            df_a = preds_data[(exp_a, s)]
            df_b = preds_data[(exp_b, s)]
            iboot = independent_bootstrap_delta(
                df_a["y_true"].to_numpy(),
                df_a["y_pred"].to_numpy(),
                df_b["y_true"].to_numpy(),
                df_b["y_pred"].to_numpy(),
                classes=classes,
                n_boot=args.n_boot,
                seed=s,
            )
            test_rows.append({
                "comparison": f"{exp_b} vs {exp_a}",
                "description": desc,
                "type": "independent_splits",
                "seed": s,
                **iboot,
                "n00_both_wrong": None,
                "n01_a_wrong_b_right": None,
                "n10_a_right_b_wrong": None,
                "n11_both_right": None,
                "chi2_cc": None,
                "p_value_exact": None,
                "significant_p05": iboot["ci_excludes_zero"],
            })

    df_tests = pd.DataFrame(test_rows)
    df_tests.to_csv(os.path.join(args.out, "table_hypothesis_tests.csv"), index=False, encoding="utf-8")

    # Đánh giá các quy tắc quyết định đã đăng ký trước (M1, M2, M3, M5)
    def _check_rule(comp_name: str) -> dict:
        sub = df_tests[df_tests["comparison"] == comp_name]
        all_pos_sig = bool(sub["positive_and_significant"].all())
        return {
            "comparison": comp_name,
            "passed_all_3_seeds": all_pos_sig,
            "mean_delta": round(float(sub["delta"].mean()), 4),
            "per_seed": sub[["seed", "macro_f1_a", "macro_f1_b", "delta", "ci95_low", "ci95_high", "p_value_exact"]].to_dict("records"),
        }

    # Kiểm tra thêm M1: CI 95% của E3 không chồng lấn với E0 ở cả 3 seed
    m1_non_overlap = all(
        boot_cache[("E3", s)]["macro_f1"]["ci95_low"] > max(
            boot_cache[("E0", s)]["macro_f1"]["ci95_high"],
            boot_cache[("E0_majority", s)]["macro_f1"]["ci95_high"],
        )
        for s in seeds
    )

    decisions = {
        "M1_baseline_beats_dummy": {
            **_check_rule("E3 vs E0_stratified"),
            "ci95_non_overlapping_all_3_seeds": m1_non_overlap,
        },
        "M2_variant_E5_beats_baseline_E3": _check_rule("E5 vs E3"),
        "Ablation_patch_E4_beats_E3": _check_rule("E4 vs E3"),
        "Ablation_norm_E5_beats_E4": _check_rule("E5 vs E4"),
        "Ablation_model_E6_vs_E5": _check_rule("E6 vs E5"),
        "M5_RQ4_leakage_E2_gt_E3": _check_rule("E2 vs E3"),
        "RQ2_dedup_E1_gt_E2": _check_rule("E1 vs E2"),
    }

    # 4. Bảng P/R/F1 từng lớp (E3 vs E5, seed 42) + Confusion Matrix + Cặp CWE cha-con (M6)
    print("[3] Vẽ Confusion Matrix và phân tích 50 mẫu lỗi của E5 (seed 42)...")
    m_e3_42 = metrics_data[("E3", 42)]["test"]
    m_e5_42 = metrics_data[("E5", 42)]["test"]
    _plot_cm(
        np.array(m_e3_42["confusion_matrix"]),
        m_e3_42["classes"],
        "Confusion Matrix – E3 Baseline (Project Split, Seed 42)",
        os.path.join(args.out, "cm_E3_seed42.png"),
    )
    _plot_cm(
        np.array(m_e5_42["confusion_matrix"]),
        m_e5_42["classes"],
        "Confusion Matrix – E5 Main Variant (Project Split, Seed 42)",
        os.path.join(args.out, "cm_E5_seed42.png"),
    )

    pc_rows = []
    for c in classes:
        c3 = m_e3_42["per_class"][c]
        c5 = m_e5_42["per_class"][c]
        pc_rows.append({
            "cwe": c,
            "support_test": c5["support"],
            "E3_precision": c3["precision"],
            "E3_recall": c3["recall"],
            "E3_f1": c3["f1"],
            "E5_precision": c5["precision"],
            "E5_recall": c5["recall"],
            "E5_f1": c5["f1"],
            "delta_f1": round(c5["f1"] - c3["f1"], 4),
        })
    pd.DataFrame(pc_rows).to_csv(os.path.join(args.out, "per_class_E3_vs_E5_seed42.csv"), index=False, encoding="utf-8")

    # Phân tích các cặp nhầm lẫn lớn nhất trên CM của E5 (seed 42)
    cm5 = np.array(m_e5_42["confusion_matrix"])
    cls5 = m_e5_42["classes"]
    conf_pairs = []
    total_mis = int(cm5.sum() - np.trace(cm5))
    same_fam_mis = 0
    for i, tc in enumerate(cls5):
        for j, pc in enumerate(cls5):
            if i != j and cm5[i, j] > 0:
                fam = same_cwe_family(tc, pc)
                if fam:
                    same_fam_mis += int(cm5[i, j])
                conf_pairs.append({
                    "true_cwe": tc,
                    "pred_cwe": pc,
                    "count": int(cm5[i, j]),
                    "pct_of_true_class": round(float(cm5[i, j] / max(cm5[i].sum(), 1)), 4),
                    "same_cwe_family": fam or "different_family",
                })
    conf_pairs.sort(key=lambda x: -x["count"])
    pd.DataFrame(conf_pairs[:25]).to_csv(os.path.join(args.out, "top_confused_cwe_pairs_E5_seed42.csv"), index=False, encoding="utf-8")

    # Lấy mẫu ngẫu nhiên 50 hunk dự đoán sai của E5 (seed 42) để phân tích lỗi (M6)
    hunks = pd.read_parquet(os.path.join(cfg["paths"]["processed"], "hunks.parquet"))
    p_e5_42 = preds_data[("E5", 42)]
    wrong = p_e5_42[~p_e5_42["correct"]].merge(
        hunks[["hunk_id", "repo_url", "hash", "filename", "lang", "n_removed", "n_added", "n_context", "removed", "added", "before"]],
        on="hunk_id",
        how="left",
    ).sort_values("hunk_id", kind="stable")
    wrong["error_category"] = [classify_error_reason(r) for _, r in wrong.iterrows()]
    err_dist_all = wrong["error_category"].value_counts().to_dict()

    rng = random.Random(42)
    chosen_ids = sorted(rng.sample(wrong["hunk_id"].tolist(), min(50, len(wrong))))
    sample_50 = wrong[wrong["hunk_id"].isin(chosen_ids)].copy()
    for col in ("removed", "added", "before"):
        sample_50[col] = sample_50[col].fillna("").str.slice(0, 240).str.replace("\n", "\\n", regex=False)
    sample_50.to_csv(os.path.join(args.out, "error_analysis_50.csv"), index=False, encoding="utf-8")
    err_dist_50 = sample_50["error_category"].value_counts().to_dict()

    summary = {
        "aggregated_results": agg_rows,
        "preregistered_decisions": decisions,
        "error_analysis_E5_seed42": {
            "total_test_samples": int(len(p_e5_42)),
            "total_misclassified": total_mis,
            "same_cwe_family_misclassified": same_fam_mis,
            "same_cwe_family_share_of_errors": round(same_fam_mis / max(total_mis, 1), 4),
            "all_errors_by_category": err_dist_all,
            "sample_50_by_category": err_dist_50,
            "top_10_confused_pairs": conf_pairs[:10],
        },
    }
    with open(os.path.join(args.out, "evaluation_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("[Done] Đã xuất toàn bộ kết quả đánh giá Bước 7 vào", args.out)
    print(json.dumps(decisions, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
