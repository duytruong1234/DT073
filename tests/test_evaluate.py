"""Unit tests cho src/evaluate.py (bootstrap CI, paired bootstrap delta, McNemar, error categorization)."""
import numpy as np
import pandas as pd

from evaluate import (
    bootstrap_ci,
    classify_error_reason,
    independent_bootstrap_delta,
    mcnemar_test,
    paired_bootstrap_delta,
    same_cwe_family,
)


def test_bootstrap_ci_bounds():
    y_true = np.array(["CWE-79"] * 20 + ["CWE-89"] * 20)
    y_pred = np.array(["CWE-79"] * 18 + ["CWE-89"] * 2 + ["CWE-89"] * 18 + ["CWE-79"] * 2)
    res = bootstrap_ci(y_true, y_pred, n_boot=200, seed=42)
    assert 0.7 <= res["macro_f1"]["ci95_low"] <= res["macro_f1"]["mean"] <= res["macro_f1"]["ci95_high"] <= 1.0
    assert 0.4 <= res["mcc"]["ci95_low"] <= res["mcc"]["ci95_high"] <= 1.0


def test_paired_and_independent_bootstrap_delta():
    y_true = np.array(["CWE-79"] * 30 + ["CWE-89"] * 30)
    pred_a = np.array(["CWE-79"] * 30 + ["CWE-79"] * 30)  # chỉ đoán đúng nửa đầu
    pred_b = y_true.copy()                                # đoán đúng 100%

    p = paired_bootstrap_delta(y_true, pred_a, pred_b, n_boot=200, seed=42)
    assert p["delta"] > 0.5
    assert p["positive_and_significant"] is True

    ind = independent_bootstrap_delta(y_true, pred_a, y_true, pred_b, n_boot=200, seed=42)
    assert ind["delta"] > 0.5
    assert ind["positive_and_significant"] is True


def test_mcnemar_test():
    y_true = np.array(["A"] * 40)
    pred_a = np.array(["B"] * 20 + ["A"] * 20)
    pred_b = np.array(["A"] * 40)
    m = mcnemar_test(y_true, pred_a, pred_b)
    assert m["n01_a_wrong_b_right"] == 20
    assert m["n10_a_right_b_wrong"] == 0
    assert m["significant_p05"] is True


def test_same_cwe_family_and_error_reason():
    assert same_cwe_family("CWE-119", "CWE-787") == "memory_buffer_bounds"
    assert same_cwe_family("CWE-79", "CWE-125") is None

    r1 = pd.Series({"y_true": "CWE-119", "y_pred": "CWE-125", "top3_correct": False, "is_add_only": False, "n_del": 3, "n_add": 3})
    assert "parent_child_or_sibling_cwe" in classify_error_reason(r1)

    r2 = pd.Series({"y_true": "CWE-79", "y_pred": "CWE-125", "top3_correct": True, "is_add_only": False, "n_del": 3, "n_add": 3})
    assert classify_error_reason(r2) == "ambiguous_rank2_or_3_in_top3"
