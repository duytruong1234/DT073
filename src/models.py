"""Bước 5f – Mô hình phân loại CWE (Dummy, TF-IDF + LogisticRegression, LinearSVC, LightGBM)
và hàm tính đầy đủ các metric theo đăng ký trước (PREREGISTRATION.md §3, §5).

Quy tắc bắt buộc:
  * TF-IDF chỉ được fit trên tập train (không bao giờ fit trên val/test).
  * Siêu tham số (C ∈ {0.1, 1.0, 10.0}) chỉ chọn trên tập val theo Macro-F1.
  * Tập test chỉ được dự đoán đúng 1 lần sau khi đã chốt mô hình trên val.
"""
from __future__ import annotations

import numpy as np
from scipy.special import softmax
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    top_k_accuracy_score,
)
from sklearn.svm import LinearSVC


def make_vectorizer(
    max_features: int = 200_000,
    min_df: int = 2,
    ngram_range: tuple[int, int] = (1, 2),
) -> TfidfVectorizer:
    """TF-IDF đúng cấu hình đã đăng ký trước trong PREREGISTRATION.md §3."""
    return TfidfVectorizer(
        token_pattern=r"\S+",
        lowercase=False,
        ngram_range=ngram_range,
        min_df=min_df,
        max_features=max_features,
        sublinear_tf=True,
        dtype=np.float64,
    )


def compute_metrics(
    y_true: list[str] | np.ndarray,
    y_pred: list[str] | np.ndarray,
    y_prob: np.ndarray | None = None,
    classes: list[str] | np.ndarray | None = None,
) -> dict:
    """Tính đầy đủ bộ metric: Macro-F1 (chính), Weighted-F1, MCC, Accuracy, Top-3 acc, P/R/F1 từng lớp, CM."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    if classes is None:
        classes = sorted(set(y_true) | set(y_pred))
    classes = list(classes)

    macro_f1 = float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0))
    mcc = float(matthews_corrcoef(y_true, y_pred)) if len(set(y_true)) > 1 else 0.0
    acc = float(accuracy_score(y_true, y_pred))

    top3 = None
    if y_prob is not None and len(classes) >= 3:
        if len(classes) == 3:
            top3 = 1.0
        else:
            try:
                top3 = float(top_k_accuracy_score(y_true, y_prob, k=3, labels=classes))
            except Exception:
                top3 = None

    p, r, f1, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average=None, zero_division=0
    )
    per_class = {
        c: {
            "precision": round(float(p[i]), 4),
            "recall": round(float(r[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(sup[i]),
        }
        for i, c in enumerate(classes)
    }
    cm = confusion_matrix(y_true, y_pred, labels=classes).tolist()

    return {
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "mcc": round(mcc, 4),
        "accuracy": round(acc, 4),
        "top3_accuracy": round(top3, 4) if top3 is not None else None,
        "n_samples": int(len(y_true)),
        "n_classes": len(classes),
        "classes": classes,
        "per_class": per_class,
        "confusion_matrix": cm,
    }


def predict_scores(clf, X) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Trả về (y_pred, y_prob, classes) cho mọi bộ phân loại sklearn/lightgbm."""
    classes = list(clf.classes_)
    y_pred = clf.predict(X)
    if hasattr(clf, "predict_proba"):
        y_prob = clf.predict_proba(X)
    elif hasattr(clf, "decision_function"):
        dec = clf.decision_function(X)
        if dec.ndim == 1:
            dec = np.column_stack([-dec, dec])
        y_prob = softmax(dec, axis=1)
    else:
        y_prob = None
    return y_pred, y_prob, classes


def fit_dummy(
    y_train: list[str] | np.ndarray,
    n_val: int,
    n_test: int,
    seed: int = 42,
) -> dict[str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list[str]]]:
    """Huấn luyện cả 2 chiến lược Dummy ('most_frequent' và 'stratified') cho E0."""
    X_tr = np.zeros((len(y_train), 1), dtype=np.float32)
    X_va = np.zeros((n_val, 1), dtype=np.float32)
    X_te = np.zeros((n_test, 1), dtype=np.float32)
    out = {}
    for name, strat in (("majority", "most_frequent"), ("stratified", "stratified")):
        clf = DummyClassifier(strategy=strat, random_state=seed)
        clf.fit(X_tr, y_train)
        va_pred, va_prob, classes = predict_scores(clf, X_va)
        te_pred, te_prob, _ = predict_scores(clf, X_te)
        out[name] = (va_pred, va_prob, te_pred, te_prob, classes)
    return out


def fit_tuned_logreg(
    X_train,
    y_train,
    X_val,
    y_val,
    c_grid: tuple[float, ...] = (0.1, 1.0, 10.0),
    seed: int = 42,
) -> tuple[LogisticRegression, dict]:
    """Chọn C ∈ {0.1, 1.0, 10.0} chỉ dựa trên Macro-F1 của tập val."""
    classes = sorted(set(y_train))
    best_clf = None
    best_c = None
    best_f1 = -1.0
    tuning_log = {}

    for c in c_grid:
        clf = LogisticRegression(
            C=float(c),
            class_weight="balanced",
            tol=1e-3,
            max_iter=300,
            random_state=seed,
        )
        clf.fit(X_train, y_train)
        val_pred = clf.predict(X_val)
        vf1 = float(f1_score(y_val, val_pred, labels=classes, average="macro", zero_division=0))
        tuning_log[str(c)] = round(vf1, 4)
        if vf1 > best_f1:
            best_f1 = vf1
            best_c = float(c)
            best_clf = clf

    return best_clf, {"best_C": best_c, "best_val_macro_f1": round(best_f1, 4), "val_macro_f1_by_C": tuning_log}


def fit_tuned_e6(
    X_train,
    y_train,
    X_val,
    y_val,
    c_grid: tuple[float, ...] = (0.1, 1.0, 10.0),
    seed: int = 42,
    run_lgbm: bool = True,
) -> tuple[object, dict]:
    """E6 (Biến thể mô hình): thử LinearSVC (C ∈ {0.1, 1.0, 10.0}) và LightGBM (early stopping trên val),
    chọn mô hình có Macro-F1 cao nhất trên tập val (không nhìn tập test).
    """
    classes = sorted(set(y_train))
    best_clf = None
    best_name = None
    best_f1 = -1.0
    tuning_log: dict[str, float] = {}

    for c in c_grid:
        clf = LinearSVC(
            C=float(c),
            class_weight="balanced",
            tol=1e-3,
            max_iter=1000,
            random_state=seed,
        )
        clf.fit(X_train, y_train)
        val_pred = clf.predict(X_val)
        vf1 = float(f1_score(y_val, val_pred, labels=classes, average="macro", zero_division=0))
        key = f"LinearSVC_C={c}"
        tuning_log[key] = round(vf1, 4)
        if vf1 > best_f1:
            best_f1 = vf1
            best_name = key
            best_clf = clf

    if run_lgbm:
        try:
            import lightgbm as lgb

            lgbm = lgb.LGBMClassifier(
                n_estimators=150,
                learning_rate=0.1,
                num_leaves=31,
                min_child_samples=50,
                colsample_bytree=0.5,
                class_weight="balanced",
                random_state=seed,
                n_jobs=8,
                verbose=-1,
            )
            lgbm.fit(
                X_train,
                y_train,
                eval_set=[(X_val, y_val)],
                callbacks=[lgb.early_stopping(stopping_rounds=20, verbose=False)],
            )
            val_pred = lgbm.predict(X_val)
            vf1 = float(f1_score(y_val, val_pred, labels=classes, average="macro", zero_division=0))
            tuning_log["LightGBM_earlystop"] = round(vf1, 4)
            if vf1 > best_f1:
                best_f1 = vf1
                best_name = "LightGBM_earlystop"
                best_clf = lgbm
        except Exception as e:
            tuning_log["LightGBM_error"] = str(e)

    return best_clf, {
        "selected_model": best_name,
        "best_val_macro_f1": round(best_f1, 4),
        "val_candidates": tuning_log,
    }
