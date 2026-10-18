"""Unit & negative tests cho src/features.py và src/models.py."""
import numpy as np
import pandas as pd
import pytest

from features import build_corpus, build_row_text, raw_tokens
from models import (
    compute_metrics,
    fit_dummy,
    fit_tuned_e6,
    fit_tuned_logreg,
    make_vectorizer,
    predict_scores,
)


def test_raw_tokens_preserves_operators_and_case():
    toks = raw_tokens("if (ptr != NULL && len >= 10) dst->val = 0;")
    assert "!=" in toks and "&&" in toks and ">=" in toks and "->" in toks
    assert "NULL" in toks


def test_feature_modes_hierarchy():
    df = pd.DataFrame([{
        "before": "char buf[10]; strcpy(buf, src);",
        "after": "char buf[10]; snprintf(buf, sizeof(buf), \"%s\", src);",
        "removed": "strcpy(buf, src);",
        "added": "snprintf(buf, sizeof(buf), \"%s\", src);",
        "section": "void foo(const char *src)",
        "lang": "C",
    }])
    b = build_corpus(df, mode="before")[0]
    p = build_corpus(df, mode="patch")[0]
    pn = build_corpus(df, mode="patch_norm")[0]

    assert "strcpy" in b and "snprintf" not in b
    assert b in p
    assert "DEL_strcpy" in p and "ADD_snprintf" in p and "LANG_C" in p
    assert p in pn
    assert "NDEL_strcpy" in pn and "NADD_snprintf" in pn and "CADD_ID" in pn


def test_feature_invalid_mode_and_empty_inputs():
    with pytest.raises(ValueError):
        build_row_text("x", mode="invalid_mode")
    assert build_row_text(None, None, None, None, mode="before") == ""
    assert "LANG_UNK" in build_row_text(None, None, None, None, mode="patch")


def test_vectorizer_never_leaks_test_vocabulary():
    train_texts = ["int a = 1 ;", "int b = 2 ;", "char * p = NULL ;", "char * q = NULL ;"]
    test_texts = ["SECRET_TEST_TOKEN_XYZ int a = 1 ;"]
    vec = make_vectorizer(min_df=1)
    vec.fit(train_texts)
    assert "SECRET_TEST_TOKEN_XYZ" not in vec.vocabulary_
    X_te = vec.transform(test_texts)
    assert X_te.shape == (1, len(vec.vocabulary_))


def test_models_and_metrics_end_to_end():
    rng = np.random.default_rng(42)
    classes = ["CWE-79", "CWE-89", "CWE-125"]
    train_texts, y_train = [], []
    val_texts, y_val = [], []
    test_texts, y_test = [], []

    patterns = {
        "CWE-79": "echo htmlspecialchars ( user_input ) ADD_htmlspecialchars LANG_PHP",
        "CWE-89": "SELECT * FROM users WHERE id = prepare ( sql ) ADD_prepare LANG_PHP",
        "CWE-125": "if ( idx >= buf_len ) return -1 ; ADD_sizeof LANG_C",
    }
    for c in classes:
        for i in range(15):
            train_texts.append(f"{patterns[c]} tok_{i % 3}")
            y_train.append(c)
        for i in range(5):
            val_texts.append(f"{patterns[c]} tok_{i % 3}")
            y_val.append(c)
            test_texts.append(f"{patterns[c]} tok_{i % 3}")
            y_test.append(c)

    vec = make_vectorizer(min_df=1)
    X_tr = vec.fit_transform(train_texts)
    X_va = vec.transform(val_texts)
    X_te = vec.transform(test_texts)

    # Dummy
    dum = fit_dummy(y_train, len(y_val), len(y_test), seed=42)
    assert "majority" in dum and "stratified" in dum
    _, _, te_pred_d, te_prob_d, cls_d = dum["majority"]
    m_dum = compute_metrics(y_test, te_pred_d, te_prob_d, cls_d)
    assert m_dum["macro_f1"] < 0.5

    # Tuned LogisticRegression
    clf, info = fit_tuned_logreg(X_tr, y_train, X_va, y_val, seed=42)
    assert info["best_C"] in (0.1, 1.0, 10.0)
    te_pred, te_prob, cls = predict_scores(clf, X_te)
    m_lr = compute_metrics(y_test, te_pred, te_prob, cls)
    assert m_lr["macro_f1"] > 0.9
    assert m_lr["top3_accuracy"] == 1.0
    assert len(m_lr["confusion_matrix"]) == 3

    # Tuned E6 (LinearSVC, skip lgbm on tiny synthetic data for speed)
    clf6, info6 = fit_tuned_e6(X_tr, y_train, X_va, y_val, seed=42, run_lgbm=False)
    assert "LinearSVC" in info6["selected_model"]
    te_pred6, te_prob6, cls6 = predict_scores(clf6, X_te)
    m_6 = compute_metrics(y_test, te_pred6, te_prob6, cls6)
    assert m_6["macro_f1"] > 0.9
