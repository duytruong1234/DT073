"""Tính lại Macro-F1 / Top-3 của 24 lần chạy (E0..E7 × 3 seed) trực tiếp từ dự đoán thô
`results/experiments/<Exp>/seed_<s>/predictions.csv` và so với `metrics.json`; kèm kiểm định
McNemar chính xác (E5 vs E3) trên cùng tập test. Không cần CSDL 12,7 GB.

Chạy:  python scripts/verify_metrics_from_predictions.py
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

import pandas as pd
from scipy.stats import binomtest
from sklearn.metrics import f1_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP_DIR = os.path.join(ROOT, "results", "experiments")
CWE_RE = re.compile(r"CWE-\d+")


def main() -> int:
    rows = []
    for f in sorted(glob.glob(os.path.join(EXP_DIR, "E*", "seed_*", "predictions.csv"))):
        exp, seed = f.split(os.sep)[-3], f.split(os.sep)[-2]
        p = pd.read_csv(f)
        mf1 = f1_score(p["y_true"], p["y_pred"], average="macro")
        top3 = sum(str(y) in set(CWE_RE.findall(str(t))) for y, t in zip(p["y_true"], p["top3_preds"])) / len(p)
        rep = json.load(open(f.replace("predictions.csv", "metrics.json"), encoding="utf-8"))["test"]
        rows.append({"exp": exp, "seed": seed, "n_test": len(p),
                     "macro_f1": round(mf1, 4), "macro_f1_reported": rep["macro_f1"],
                     "top3": round(top3, 4), "top3_reported": rep["top3_accuracy"]})
    if not rows:
        print("Không tìm thấy predictions.csv trong results/experiments/")
        return 1
    df = pd.DataFrame(rows)
    print(df.to_string(index=False))
    print("\nTrung bình Macro-F1 theo thí nghiệm:", df.groupby("exp")["macro_f1"].mean().round(4).to_dict())
    max_diff = (df["macro_f1"] - df["macro_f1_reported"]).abs().max()
    print(f"Sai lệch Macro-F1 lớn nhất so với metrics.json: {max_diff:.4f}")
    # E0 (Dummy) lưu top3 của bộ majority trong metrics nên có thể khác dự đoán stratified -> bỏ qua khi so top3
    t3 = df[df["exp"] != "E0"]
    print(f"Sai lệch Top-3 lớn nhất (E1..E7): {(t3['top3'] - t3['top3_reported']).abs().max():.4f}")

    print("\nMcNemar chính xác – E5 (biến thể) vs E3 (baseline), cùng tập test:")
    for seed in ["seed_42", "seed_123", "seed_2024"]:
        a = pd.read_csv(os.path.join(EXP_DIR, "E3", seed, "predictions.csv"))
        b = pd.read_csv(os.path.join(EXP_DIR, "E5", seed, "predictions.csv"))
        ab = a.merge(b, on="hunk_id", suffixes=("_a", "_b"))
        ra = ab["y_true_a"] == ab["y_pred_a"]
        rb = ab["y_true_b"] == ab["y_pred_b"]
        n01, n10 = int((~ra & rb).sum()), int((ra & ~rb).sum())
        pval = binomtest(n01, n01 + n10, 0.5).pvalue
        print(f"  {seed}: E3 sai/E5 đúng = {n01}, E3 đúng/E5 sai = {n10}, p = {pval:.2e}")
    return 0 if max_diff < 1e-4 else 2


if __name__ == "__main__":
    sys.exit(main())
