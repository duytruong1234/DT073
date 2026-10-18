"""Bước 5e – Chia train/val/test chống rò rỉ (phục vụ RQ4: random vs project vs time).

Nhóm rò rỉ (`leak_group`) = thành phần liên thông nối các mẫu có chung:
    repo (kể cả fork) · CVE · cụm gần trùng (dup_near)
-> split "project" đảm bảo KHÔNG nhóm nào nằm ở cả train và test (mạnh hơn chỉ group theo repo,
   vì cùng CVE được sửa ở nhiều fork – đã thấy trong CVEfixes, VD CVE-2008-1897 ở 8 fork Asterisk).

Mọi phép chia tất định theo seed.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from dedup import UnionFind


def leak_groups(df: pd.DataFrame, dup_col: str = "dup_near") -> pd.Series:
    keys = []
    for r in df.itertuples(index=False):
        k = [f"repo:{u}" for u in (r.repo_urls if isinstance(r.repo_urls, (list, np.ndarray)) else [r.repo_url])]
        k += [f"cve:{c}" for c in (r.cve_ids if isinstance(r.cve_ids, (list, np.ndarray)) else [])]
        if dup_col in df.columns:
            k.append(f"dup:{getattr(r, dup_col)}")
        keys.append(k)
    uf = UnionFind(sorted({x for k in keys for x in k}))
    for k in keys:
        for x in k[1:]:
            uf.union(k[0], x)
    roots = [uf.find(k[0]) for k in keys]
    codes, _ = pd.factorize(pd.Series(roots), sort=True)
    return pd.Series(codes, index=df.index, name="leak_group")


def _stratified_group_holdout(y, groups, frac, seed):
    """Chọn ~frac số mẫu làm holdout theo NHÓM, cân bằng nhãn bằng StratifiedGroupKFold."""
    from sklearn.model_selection import StratifiedGroupKFold
    n_splits = max(2, int(round(1 / frac)))
    y = np.asarray(y)
    # lớp quá hiếm (< n_splits) làm StratifiedGroupKFold cảnh báo -> gộp tạm để phân tầng
    vals, cnt = np.unique(y, return_counts=True)
    rare = set(vals[cnt < n_splits])
    y_strat = np.array(["__rare__" if v in rare else v for v in y])
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    _, hold = next(sgkf.split(np.zeros(len(y)), y_strat, groups))
    mask = np.zeros(len(y), dtype=bool)
    mask[hold] = True
    return mask


def split_random(df, label_col, test_size, val_size, seed):
    from sklearn.model_selection import train_test_split
    idx = np.arange(len(df))
    y = df[label_col].values
    strat = y if pd.Series(y).value_counts().min() >= 2 else None
    tr, te = train_test_split(idx, test_size=test_size, random_state=seed, stratify=strat)
    y_tr = y[tr]
    strat2 = y_tr if pd.Series(y_tr).value_counts().min() >= 2 else None
    tr, va = train_test_split(tr, test_size=val_size / (1 - test_size), random_state=seed, stratify=strat2)
    out = np.empty(len(df), dtype=object)
    out[tr], out[va], out[te] = "train", "val", "test"
    return pd.Series(out, index=df.index)


def split_project(df, label_col, groups, test_size, val_size, seed):
    y = df[label_col].values
    g = groups.values
    test = _stratified_group_holdout(y, g, test_size, seed)
    rest = ~test
    val_rest = _stratified_group_holdout(y[rest], g[rest], val_size / (1 - test_size), seed + 1)
    out = np.full(len(df), "train", dtype=object)
    out[test] = "test"
    out[np.where(rest)[0][val_rest]] = "val"
    return pd.Series(out, index=df.index)


def split_time(df, groups, cutoff_year, val_size, seed):
    """train/val: năm < cutoff; test: năm ≥ cutoff. Mẫu test thuộc nhóm đã có trong train -> 'drop'."""
    year = pd.to_numeric(df["year"], errors="coerce")
    out = np.where(year >= cutoff_year, "test", "train").astype(object)
    rng = np.random.default_rng(seed)
    train_groups = np.unique(groups[out == "train"])
    val_groups = set(rng.choice(train_groups, size=int(round(len(train_groups) * val_size)), replace=False)) \
        if len(train_groups) else set()
    is_val = groups.isin(val_groups).values & (out == "train")
    out[is_val] = "val"
    seen = set(groups[(out == "train") | (out == "val")])
    out[(out == "test") & groups.isin(seen).values] = "drop"
    return pd.Series(out, index=df.index)


def make_splits(df: pd.DataFrame, cfg_split: dict, seed: int, label_col: str = "label") -> pd.DataFrame:
    out = df.copy()
    out["leak_group"] = leak_groups(out)
    ts, vs = cfg_split.get("test_size", 0.2), cfg_split.get("val_size", 0.1)
    for s in cfg_split.get("strategies", ["random", "project", "time"]):
        if s == "random":
            out["split_random"] = split_random(out, label_col, ts, vs, seed)
        elif s == "project":
            out["split_project"] = split_project(out, label_col, out["leak_group"], ts, vs, seed)
        elif s == "time":
            out["split_time"] = split_time(out, out["leak_group"], cfg_split.get("time_cutoff_year", 2022), vs, seed)
    return out


def leakage_report(df: pd.DataFrame, split_col: str) -> dict:
    """Đếm phần tử dùng chung giữa train và test theo từng loại khóa – kiểm chứng chống rò rỉ."""
    tr, te = df[df[split_col] == "train"], df[df[split_col] == "test"]

    def flat(sub, col):
        s = set()
        for v in sub[col]:
            s.update(v if isinstance(v, (list, np.ndarray)) else [v])
        return s

    rep = {"n_train": int(len(tr)), "n_test": int(len(te))}
    for name, col in (("repo", "repo_urls"), ("cve", "cve_ids")):
        if col in df:
            rep[f"shared_{name}"] = len(flat(tr, col) & flat(te, col))
    for col in ("dup_exact", "dup_normalized", "dup_near", "leak_group"):
        if col in df:
            rep[f"shared_{col}"] = len(set(tr[col]) & set(te[col]))
    return rep
