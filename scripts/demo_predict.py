"""Bước 8 – Demo dự đoán Top-3 CWE từ một đoạn unified diff (hoặc hunk mẫu).
Chỉ phân tích tĩnh chuỗi diff bằng tree-sitter + TF-IDF (KHÔNG biên dịch/thực thi mã).

Ví dụ chạy:
    .venv\\Scripts\\python scripts/demo_predict.py
    .venv\\Scripts\\python scripts/demo_predict.py --lang C --diff-file sample.patch
"""
from __future__ import annotations

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

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from features import build_row_text  # noqa: E402
from hunks import mask_emails, parse_diff  # noqa: E402
from models import predict_scores  # noqa: E402

SAMPLE_DIFFS = [
    (
        "C",
        """@@ -42,4 +42,5 @@ void copy_name(const char *user_in)
-    char buf[64];
-    strcpy(buf, user_in);
+    char buf[64];
+    snprintf(buf, sizeof(buf), "%s", user_in);
""",
    ),
    (
        "PHP",
        """@@ -15,3 +15,3 @@ function renderProfile($req)
-    echo "<div class='bio'>" . $_GET['bio'] . "</div>";
+    echo "<div class='bio'>" . htmlspecialchars($_GET['bio'], ENT_QUOTES, 'UTF-8') . "</div>";
""",
    ),
    (
        "Python",
        """@@ -20,3 +20,4 @@ def get_user_record(cursor, username):
-    cursor.execute("SELECT * FROM accounts WHERE username = '%s'" % username)
+    cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
""",
    ),
]


def predict_diff(bundle: dict, diff_text: str, lang: str = "C") -> list[dict]:
    vec = bundle["vectorizer"]
    clf = bundle["classifier"]
    mode = bundle.get("feature_mode", "patch_norm")

    hunks = parse_diff(diff_text)
    if not hunks:
        return []
    out = []
    for h in hunks:
        b, _ = mask_emails(h.before)
        a, _ = mask_emails(h.after)
        rem, _ = mask_emails(h.removed)
        add, _ = mask_emails(h.added)
        sec, _ = mask_emails(h.section)
        txt = build_row_text(before=b, after=a, removed=rem, added=add, section=sec, lang=lang, mode=mode)
        X = vec.transform([txt])
        pred, prob, classes = predict_scores(clf, X)
        top_idx = np.argsort(-prob[0])[:3]
        top3 = [{"rank": r + 1, "cwe": classes[i], "score": round(float(prob[0][i]), 4)} for r, i in enumerate(top_idx)]
        out.append({
            "hunk_idx": h.idx,
            "lang": lang,
            "predicted_cwe": str(pred[0]),
            "top3": top3,
            "removed": rem,
            "added": add,
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join("results", "models", "E5_seed42.joblib"))
    ap.add_argument("--lang", default="C")
    ap.add_argument("--diff-file", default=None)
    args = ap.parse_args()

    if not os.path.exists(args.model):
        raise SystemExit(f"Không tìm thấy model tại {args.model}. Hãy chạy scripts/run_experiments.py trước.")
    bundle = joblib.load(args.model)

    if args.diff_file:
        with open(args.diff_file, encoding="utf-8") as f:
            diff_text = f.read()
        res = predict_diff(bundle, diff_text, lang=args.lang)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("=== DEMO DỰ ĐOÁN TOP-3 CWE TRÊN 3 BẢN VÁ MẪU (Model: E5_seed42) ===")
        for lang, diff_text in SAMPLE_DIFFS:
            res = predict_diff(bundle, diff_text, lang=lang)
            print(f"\n--- Ngôn ngữ: {lang} ---")
            print(diff_text.strip())
            print("-> Kết quả dự đoán:", json.dumps(res[0]["top3"], ensure_ascii=False))


if __name__ == "__main__":
    main()
