"""Bước 7 – Thống kê thực nghiệm: Bootstrap CI 95% (1 000 lần), Paired Bootstrap ΔMacro-F1,
kiểm định McNemar, phân tích cặp CWE cha-con và phân loại nguyên nhân lỗi (M0..M6).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.metrics import f1_score, matthews_corrcoef

# Các nhóm CWE có quan hệ cha-con hoặc chồng lấn ngữ nghĩa trực tiếp trong CWE-1000
CWE_HIERARCHY_GROUPS = {
    "memory_buffer_bounds": {"CWE-119", "CWE-125", "CWE-787", "CWE-416", "CWE-476", "CWE-190"},
    "injection_and_input": {"CWE-20", "CWE-79", "CWE-89", "CWE-78", "CWE-94"},
    "auth_and_access": {"CWE-287", "CWE-863", "CWE-352", "CWE-200"},
    "path_and_resource": {"CWE-22", "CWE-400"},
}


def bootstrap_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    classes: list[str] | None = None,
    n_boot: int = 1000,
    seed: int = 42,
) -> dict[str, dict[str, float]]:
    """Bootstrap 1 000 lần trên tập test cho Macro-F1, Weighted-F1 và MCC."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    if classes is None:
        classes = sorted(set(y_true) | set(y_pred))
    rng = np.random.default_rng(seed)
    n = len(y_true)

    mf1_s, wf1_s, mcc_s = np.empty(n_boot), np.empty(n_boot), np.empty(n_boot)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        yt, yp = y_true[idx], y_pred[idx]
        mf1_s[i] = f1_score(yt, yp, labels=classes, average="macro", zero_division=0)
        wf1_s[i] = f1_score(yt, yp, labels=classes, average="weighted", zero_division=0)
        mcc_s[i] = matthews_corrcoef(yt, yp) if len(set(yt)) > 1 else 0.0

    def _stat(arr):
        lo, hi = np.percentile(arr, [2.5, 97.5])
        return {"mean": round(float(arr.mean()), 4), "ci95_low": round(float(lo), 4), "ci95_high": round(float(hi), 4)}

    return {
        "macro_f1": _stat(mf1_s),
        "weighted_f1": _stat(wf1_s),
        "mcc": _stat(mcc_s),
    }


def paired_bootstrap_delta(
    y_true: np.ndarray,
    pred_a: np.ndarray,
    pred_b: np.ndarray,
    classes: list[str] | None = None,
    n_boot: int = 1000,
    seed: int = 42,
) -> dict:
    """Paired bootstrap CI 95% (1 000 lần) cho ΔMacro-F1 = Macro-F1(B) - Macro-F1(A) trên cùng tập test."""
    y_true = np.asarray(y_true)
    pred_a = np.asarray(pred_a)
    pred_b = np.asarray(pred_b)
    assert len(y_true) == len(pred_a) == len(pred_b), "Paired bootstrap requires identical test samples!"
    if classes is None:
        classes = sorted(set(y_true) | set(pred_a) | set(pred_b))

    obs_a = float(f1_score(y_true, pred_a, labels=classes, average="macro", zero_division=0))
    obs_b = float(f1_score(y_true, pred_b, labels=classes, average="macro", zero_division=0))
    obs_delta = obs_b - obs_a

    rng = np.random.default_rng(seed)
    n = len(y_true)
    deltas = np.empty(n_boot)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        yt = y_true[idx]
        fa = f1_score(yt, pred_a[idx], labels=classes, average="macro", zero_division=0)
        fb = f1_score(yt, pred_b[idx], labels=classes, average="macro", zero_division=0)
        deltas[i] = fb - fa

    lo, hi = np.percentile(deltas, [2.5, 97.5])
    p_one_sided = float(np.mean(deltas <= 0.0)) if obs_delta >= 0 else float(np.mean(deltas >= 0.0))
    return {
        "macro_f1_a": round(obs_a, 4),
        "macro_f1_b": round(obs_b, 4),
        "delta": round(obs_delta, 4),
        "ci95_low": round(float(lo), 4),
        "ci95_high": round(float(hi), 4),
        "ci_excludes_zero": bool(lo > 0.0 or hi < 0.0),
        "positive_and_significant": bool(obs_delta > 0.0 and lo > 0.0),
        "p_boot_one_sided": round(p_one_sided, 4),
    }


def independent_bootstrap_delta(
    y_true_a: np.ndarray,
    pred_a: np.ndarray,
    y_true_b: np.ndarray,
    pred_b: np.ndarray,
    classes: list[str] | None = None,
    n_boot: int = 1000,
    seed: int = 42,
) -> dict:
    """Bootstrap CI 95% cho ΔMacro-F1 = Macro-F1(B) - Macro-F1(A) khi 2 phép chia có tập test khác nhau (VD: E2 vs E3)."""
    y_true_a, pred_a = np.asarray(y_true_a), np.asarray(pred_a)
    y_true_b, pred_b = np.asarray(y_true_b), np.asarray(pred_b)
    if classes is None:
        classes = sorted(set(y_true_a) | set(y_true_b))

    obs_a = float(f1_score(y_true_a, pred_a, labels=classes, average="macro", zero_division=0))
    obs_b = float(f1_score(y_true_b, pred_b, labels=classes, average="macro", zero_division=0))
    obs_delta = obs_b - obs_a

    rng = np.random.default_rng(seed)
    na, nb = len(y_true_a), len(y_true_b)
    deltas = np.empty(n_boot)
    for i in range(n_boot):
        ia = rng.integers(0, na, na)
        ib = rng.integers(0, nb, nb)
        fa = f1_score(y_true_a[ia], pred_a[ia], labels=classes, average="macro", zero_division=0)
        fb = f1_score(y_true_b[ib], pred_b[ib], labels=classes, average="macro", zero_division=0)
        deltas[i] = fb - fa

    lo, hi = np.percentile(deltas, [2.5, 97.5])
    return {
        "macro_f1_a": round(obs_a, 4),
        "macro_f1_b": round(obs_b, 4),
        "delta": round(obs_delta, 4),
        "ci95_low": round(float(lo), 4),
        "ci95_high": round(float(hi), 4),
        "ci_excludes_zero": bool(lo > 0.0 or hi < 0.0),
        "positive_and_significant": bool(obs_delta > 0.0 and lo > 0.0),
    }


def mcnemar_test(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> dict:
    """Kiểm định McNemar (exact binomial + chi2 hiệu chỉnh liên tục) trên 2 mô hình cùng tập test."""
    y_true = np.asarray(y_true)
    ca = np.asarray(pred_a) == y_true
    cb = np.asarray(pred_b) == y_true
    n00 = int(np.sum(~ca & ~cb))
    n01 = int(np.sum(~ca & cb))  # A sai, B đúng
    n10 = int(np.sum(ca & ~cb))  # A đúng, B sai
    n11 = int(np.sum(ca & cb))
    discordant = n01 + n10
    if discordant == 0:
        chi2 = 0.0
        p_exact = 1.0
    else:
        chi2 = float((abs(n01 - n10) - 1.0) ** 2 / discordant)
        p_exact = float(binomtest(min(n01, n10), discordant, 0.5, alternative="two-sided").pvalue)
    return {
        "n00_both_wrong": n00,
        "n01_a_wrong_b_right": n01,
        "n10_a_right_b_wrong": n10,
        "n11_both_right": n11,
        "chi2_cc": round(chi2, 4),
        "p_value_exact": round(p_exact, 6),
        "significant_p05": bool(p_exact < 0.05),
    }


def same_cwe_family(cwe_a: str, cwe_b: str) -> str | None:
    """Kiểm tra 2 nhãn CWE có thuộc cùng nhóm cha-con/ngữ nghĩa gần nhau không."""
    if cwe_a == cwe_b:
        return None
    for fam, members in CWE_HIERARCHY_GROUPS.items():
        if cwe_a in members and cwe_b in members:
            return fam
    return None


def classify_error_reason(row: pd.Series) -> str:
    """Phân loại nguyên nhân dự đoán sai cho phân tích lỗi (M6)."""
    fam = same_cwe_family(row["y_true"], row["y_pred"])
    if fam is not None:
        return f"parent_child_or_sibling_cwe ({fam})"
    if bool(row.get("top3_correct", False)):
        return "ambiguous_rank2_or_3_in_top3"
    n_rem = int(row.get("n_removed", row.get("n_del", 0)) or 0)
    n_add = int(row.get("n_added", row.get("n_add", 0)) or 0)
    if bool(row.get("is_add_only", False)) or (n_rem == 0 and n_add > 0):
        return "add_only_patch_without_deleted_lines"
    if n_rem + n_add <= 2:
        return "very_short_hunk_1_2_changed_lines"
    return "cross_domain_or_project_specific_context"

