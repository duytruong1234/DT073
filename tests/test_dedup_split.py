"""Unit test cho src/dedup.py và src/split.py."""
import pandas as pd

from dedup import cross_split_duplicates, deduplicate, duplicate_stats
from normalize import tokenize
from split import leakage_report, make_splits

SEP = "<SEP>"


def make_df(rows):
    df = pd.DataFrame(rows)
    df["norm_before"] = [" ".join(tokenize(b, "C")) for b in df.before]
    df["norm_after"] = [" ".join(tokenize(a, "C")) for a in df.after]
    df["norm_tokens"] = [tokenize(b, "C") + [SEP] + tokenize(a, "C") for b, a in zip(df.before, df.after)]
    return df


LONG = "".join(f"v{i} = g{i}(v{i - 1}, {i});\n" for i in range(1, 40))
ROWS = [
    # h1 & h2: trùng nguyên văn (h2 là fork, commit muộn hơn)
    dict(hunk_id="h1", committer_date="2020-01-01", before="strcpy(a, b);\n", after="strncpy(a, b, n);\n", label="CWE-787"),
    dict(hunk_id="h2", committer_date="2021-01-01", before="strcpy(a, b);\n", after="strncpy(a, b, n);\n", label="CWE-787"),
    # h3: chỉ khác tên biến + comment -> trùng mức normalized; nhãn khác -> xung đột nhãn
    dict(hunk_id="h3", committer_date="2019-06-01", before="strcpy(x, y); // c\n", after="strncpy(x, y, m);\n", label="CWE-120"),
    # h4/h5: dài, khác nhau CẤU TRÚC 1 dòng cuối (không chỉ tên biến) -> gần trùng (near), không trùng normalized
    dict(hunk_id="h4", committer_date="2018-01-01", before=LONG + "free(p);\n", after=LONG + "p = NULL;\n", label="CWE-416"),
    dict(hunk_id="h5", committer_date="2018-02-01", before=LONG + "free(p);\n", after=LONG + "p = p - 1;\n", label="CWE-416"),
    # h6: khác hẳn
    dict(hunk_id="h6", committer_date="2022-01-01", before="eval(input);\n", after="safe(input);\n", label="CWE-94"),
]


def test_three_levels_nested_and_representative():
    out = deduplicate(make_df(ROWS), near_threshold=0.8, num_perm=128)
    d = out.set_index("hunk_id")
    assert d.loc["h1", "dup_exact"] == d.loc["h2", "dup_exact"] == "h1"   # đại diện = commit sớm hơn
    assert d.loc["h3", "dup_exact"] == "h3"
    assert d.loc["h1", "dup_normalized"] == d.loc["h3", "dup_normalized"] == "h3"  # h3 sớm nhất
    assert d.loc["h4", "dup_normalized"] != d.loc["h5", "dup_normalized"]
    assert d.loc["h4", "dup_near"] == d.loc["h5", "dup_near"] == "h4"
    assert d.loc["h6", "dup_near"] == "h6"
    # lồng nhau: cùng cụm exact => cùng cụm normalized => cùng cụm near
    for a, b in [("h1", "h2")]:
        assert d.loc[a, "dup_normalized"] == d.loc[b, "dup_normalized"]
        assert d.loc[a, "dup_near"] == d.loc[b, "dup_near"]


def test_stats_and_label_conflict():
    out = deduplicate(make_df(ROWS), near_threshold=0.8)
    s = duplicate_stats(out, "label")
    assert s["exact"]["n_clusters"] == 5 and s["exact"]["duplicate_rate"] == round(1 - 5 / 6, 4)
    assert s["normalized"]["n_clusters"] == 4
    assert s["near"]["n_clusters"] == 3
    assert s["normalized"]["label_conflict_clusters"] == 1      # CWE-787 vs CWE-120


def test_deterministic():
    a = deduplicate(make_df(ROWS), near_threshold=0.8)
    b = deduplicate(make_df(list(reversed(ROWS))), near_threshold=0.8).set_index("hunk_id").loc[a.hunk_id].reset_index()
    for c in ("dup_exact", "dup_normalized", "dup_near"):
        assert list(a[c]) == list(b[c])


# ---------------------------------------------------------------- split ----
def split_df(n=240):
    rows = []
    for i in range(n):
        repo = f"https://github.com/o/r{i % 30}"
        rows.append(dict(hunk_id=f"h{i:04d}", repo_url=repo, repo_urls=[repo],
                         cve_ids=[f"CVE-{i % 60}"], dup_near=f"h{i:04d}", label=f"CWE-{i % 4}",
                         year=str(2015 + i % 9)))
    # 1 CVE được sửa ở 2 repo khác nhau (fork) -> phải chung nhóm rò rỉ
    rows[0]["cve_ids"] = ["CVE-FORK"]
    rows[1]["cve_ids"] = ["CVE-FORK"]
    return pd.DataFrame(rows)


CFG = {"strategies": ["random", "project", "time"], "test_size": 0.2, "val_size": 0.1, "time_cutoff_year": 2021}


def test_project_split_has_no_leakage():
    sp = make_splits(split_df(), CFG, seed=42)
    rep = leakage_report(sp, "split_project")
    assert rep["shared_repo"] == 0 and rep["shared_cve"] == 0 and rep["shared_leak_group"] == 0
    assert 0.1 < rep["n_test"] / len(sp) < 0.35
    assert sp.loc[0, "leak_group"] == sp.loc[1, "leak_group"]


def test_random_split_leaks_and_project_does_not():
    sp = make_splits(split_df(), CFG, seed=42)
    assert leakage_report(sp, "split_random")["shared_repo"] > 0   # minh họa vì sao random split bị rò rỉ


def test_time_split_order_and_drop():
    sp = make_splits(split_df(), CFG, seed=42)
    y = pd.to_numeric(sp["year"])
    assert (y[sp.split_time == "test"] >= 2021).all()
    assert (y[sp.split_time.isin(["train", "val"])] < 2021).all()
    rep = leakage_report(sp, "split_time")
    assert rep["shared_cve"] == 0 and rep["shared_dup_near"] == 0 and rep["shared_time_group"] == 0


def test_split_deterministic_with_seed():
    a, b = make_splits(split_df(), CFG, 7), make_splits(split_df(), CFG, 7)
    c = make_splits(split_df(), CFG, 8)
    assert a.split_project.equals(b.split_project) and a.split_random.equals(b.split_random)
    assert not a.split_random.equals(c.split_random)


def test_cross_split_duplicates():
    df = pd.DataFrame({"dup_normalized": ["a", "a", "b", "c"], "s": ["train", "test", "test", "val"]})
    r = cross_split_duplicates(df, "s", "normalized")
    assert r["test"] == {"n": 2, "dup_in_train": 1, "rate": 0.5}
