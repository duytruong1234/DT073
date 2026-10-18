"""Bước 5d – Khử trùng lặp 3 mức trên hunk (đo duplicate rate – metric bắt buộc của đề).

  exact      : trùng nguyên văn before+after
  normalized : trùng sau chuẩn hóa tree-sitter (bỏ comment/khoảng trắng, đổi định danh)
  near       : gần trùng – MinHash LSH trên shingle token chuẩn hóa, Jaccard ≥ ngưỡng

Mỗi mức gán `dup_<level>` = id cụm (= hunk đại diện). Đại diện được chọn TẤT ĐỊNH:
commit sớm nhất, rồi hunk_id nhỏ nhất (bản sửa gốc trước các bản fork/cherry-pick).
Các mức lồng nhau: exact ⊆ normalized ⊆ near.
"""
from __future__ import annotations

import hashlib

import pandas as pd


class UnionFind:
    def __init__(self, items):
        self.p = {x: x for x in items}

    def find(self, x):
        root = x
        while self.p[root] != root:
            root = self.p[root]
        while self.p[x] != root:
            self.p[x], x = root, self.p[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if rb < ra:
                ra, rb = rb, ra
            self.p[rb] = ra


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "surrogatepass")).hexdigest()


def _order(df: pd.DataFrame) -> pd.Series:
    """Thứ hạng tất định: commit sớm nhất trước, rồi hunk_id."""
    key = df[["committer_date", "hunk_id"]].astype(str)
    return key.apply(tuple, axis=1).rank(method="first").astype(int)


def _assign(df: pd.DataFrame, groups: pd.Series, order: pd.Series) -> pd.Series:
    """Map mỗi dòng -> hunk_id đại diện (thứ hạng nhỏ nhất) trong nhóm."""
    tmp = pd.DataFrame({"g": groups.values, "o": order.values, "h": df["hunk_id"].values})
    rep = tmp.sort_values("o").drop_duplicates("g").set_index("g")["h"]
    return pd.Series(tmp["g"].map(rep).values, index=df.index)


def shingles(tokens: list[str], k: int) -> set[bytes]:
    if len(tokens) < k:
        return {" ".join(tokens).encode()} if tokens else set()
    return {" ".join(tokens[i:i + k]).encode() for i in range(len(tokens) - k + 1)}


def near_duplicate_groups(df: pd.DataFrame, token_col: str, base_groups: pd.Series,  # mã nhóm kiểu int
                          threshold: float = 0.9, num_perm: int = 128, k: int = 3,
                          seed: int = 1) -> pd.Series:
    """Gom cụm gần trùng bằng MinHash LSH; khởi đầu từ nhóm normalized (base_groups)."""
    from datasketch import MinHash, MinHashLSH

    uf = UnionFind(list(base_groups.unique()))
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    sigs = {}
    # mỗi nhóm normalized chỉ cần 1 chữ ký (các phần tử đã giống nhau sau chuẩn hóa)
    first = df.groupby(base_groups, sort=True).head(1)
    for g, toks in zip(base_groups.loc[first.index], first[token_col]):
        sh = shingles(toks, k)
        m = MinHash(num_perm=num_perm, seed=seed)
        if sh:
            m.update_batch(list(sh))
        sigs[g] = m
        lsh.insert(str(g), m)
    for g, m in sigs.items():
        for other in lsh.query(m):
            o = int(other)
            if o != g and m.jaccard(sigs[o]) >= threshold:
                uf.union(g, o)
    return base_groups.map(uf.find)


def deduplicate(df: pd.DataFrame, norm_before: str = "norm_before", norm_after: str = "norm_after",
                tokens_col: str = "norm_tokens", near_threshold: float = 0.9, num_perm: int = 128,
                shingle_size: int = 3, levels=("exact", "normalized", "near")) -> pd.DataFrame:
    """Thêm cột dup_exact / dup_normalized / dup_near (id hunk đại diện) và is_rep_<level>."""
    out = df.copy()
    order = _order(out)
    exact_key = (out["before"].fillna("") + "\x00" + out["after"].fillna("")).map(_sha1)
    out["dup_exact"] = _assign(out, exact_key, order)
    if "normalized" in levels or "near" in levels:
        norm_key = (out[norm_before].fillna("") + "\x00" + out[norm_after].fillna("")).map(_sha1)
        # lồng nhau: exact ⊆ normalized
        uf = UnionFind(sorted(set(norm_key) | set(exact_key)))
        for a, b in zip(exact_key, norm_key):
            uf.union(a, b)
        ng = norm_key.map(uf.find)
        out["dup_normalized"] = _assign(out, ng, order)
        if "near" in levels:
            codes = pd.Series(pd.factorize(ng, sort=True)[0], index=out.index)
            near = near_duplicate_groups(out, tokens_col, codes, near_threshold, num_perm, shingle_size)
            out["dup_near"] = _assign(out, near, order)
    for lv in ("exact", "normalized", "near"):
        col = f"dup_{lv}"
        if col in out:
            out[f"is_rep_{lv}"] = out[col] == out["hunk_id"]
    return out


def duplicate_stats(df: pd.DataFrame, label_col: str | None = "label") -> dict:
    """duplicate_rate = 1 - #cụm/#hunk; label_conflict = cụm có >1 nhãn khác nhau."""
    n = len(df)
    res = {"n_hunks": n}
    for lv in ("exact", "normalized", "near"):
        col = f"dup_{lv}"
        if col not in df:
            continue
        n_clusters = df[col].nunique()
        sizes = df.groupby(col).size()
        d = {"n_clusters": int(n_clusters),
             "duplicate_rate": round(1 - n_clusters / n, 4) if n else None,
             "max_cluster_size": int(sizes.max()) if n else 0,
             "rows_in_dup_clusters": int(sizes[sizes > 1].sum()) if n else 0}
        if label_col and label_col in df:
            lab = df[df[label_col].notna()]
            nl = lab.groupby(col)[label_col].nunique()
            d["label_conflict_clusters"] = int((nl > 1).sum())
            d["label_conflict_rows"] = int(lab[lab[col].isin(nl[nl > 1].index)].shape[0])
        res[lv] = d
    return res


def cross_split_duplicates(df: pd.DataFrame, split_col: str, level: str = "normalized") -> dict:
    """Số hunk test/val có bản trùng (cùng cụm) nằm trong train – đo rò rỉ do trùng lặp."""
    col = f"dup_{level}"
    train = set(df.loc[df[split_col] == "train", col])
    res = {}
    for part in ("val", "test"):
        sub = df[df[split_col] == part]
        leak = int(sub[col].isin(train).sum())
        res[part] = {"n": int(len(sub)), "dup_in_train": leak,
                     "rate": round(leak / len(sub), 4) if len(sub) else None}
    return res

