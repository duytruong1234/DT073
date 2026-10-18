"""Integration test: DB giả lập schema CVEfixes (có nhãn CWE) -> scripts/build_dataset.py end-to-end.

Kiểm tra: chạy 2 lần cho cùng checksum; có cột split; project split không rò rỉ repo/CVE.
"""
import json
import os
import sqlite3
import subprocess
import sys

import pandas as pd
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CWES = ["CWE-787", "CWE-79", "CWE-89"]
STMTS = ["a = a + b;", "a = a - b;", "a = a * b;", "if (a > b) a = b;", "while (a < b) a++;",
         "memcpy(a, b, n);", "free(a);", "a = malloc(n);", "strcpy(a, b);", "return a;",
         "for (i = 0; i < n; i++) a[i] = 0;", "a = b ? a : b;", "a <<= 1;", "a |= b;",
         "if (!a) goto out;", "printf(a);"]


def fake_body(i):
    import hashlib
    hx = hashlib.md5(str(i).encode()).hexdigest()[:12]
    return [STMTS[int(c, 16)] for c in hx]


def build_fake_db(path):
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);
    CREATE TABLE commits (hash TEXT, repo_url TEXT, committer_date TEXT, merge TEXT, parents TEXT);
    CREATE TABLE file_change (file_change_id TEXT, hash TEXT, filename TEXT, old_path TEXT, new_path TEXT,
        change_type TEXT, diff TEXT, num_lines_added TEXT, num_lines_deleted TEXT, code_before BLOB,
        code_after BLOB, programming_language TEXT);
    CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);
    """)
    fc = 0
    for i in range(90):
        h = f"{i:040x}"
        repo = f"https://github.com/org/repo{i % 15}"
        cve = f"CVE-2020-{i:04d}"
        cwe = CWES[i % 3]
        con.execute("INSERT INTO fixes VALUES (?,?,?)", (cve, h, repo))
        con.execute("INSERT INTO commits VALUES (?,?,?,?,?)",
                    (h, repo, f"{2016 + i % 8}-03-01 10:00:00+00:00", "False", "[]"))
        con.execute("INSERT INTO cwe_classification VALUES (?,?)", (cve, cwe))
        body = fake_body(i)
        diff = (f"@@ -1,{len(body) + 2} +1,{len(body) + 2} @@ int f{i}()\n"
                + "".join(f" {ln}\n" for ln in body)
                + f"-call_{cwe[4:]}(a, {i});\n+safe_{cwe[4:]}(a, {i}, n);\n return a;\n")
        fc += 1
        con.execute("INSERT INTO file_change VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (str(1000 + fc), h, f"f{i}.c", f"f{i}.c", f"f{i}.c", "ModificationType.MODIFY",
                     diff, "1", "1", None, None, "C"))
    # 1 file không phải mã nguồn + 1 diff rỗng -> phải bị loại ở validate
    con.execute("INSERT INTO file_change VALUES ('9001', ?, 'README.md', '', '', 'ModificationType.MODIFY',"
                " '@@ -1 +1 @@\n-a\n+b\n', '1', '1', NULL, NULL, 'Markdown')", (f"{0:040x}",))
    con.execute("INSERT INTO file_change VALUES ('9002', ?, 'g.c', '', '', 'ModificationType.MODIFY',"
                " '', '0', '0', NULL, NULL, 'C')", (f"{1:040x}",))
    con.commit()
    con.close()


def run(db, out):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_dataset.py"), "--db", db, "--out", out],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    return json.load(open(os.path.join(out, "MANIFEST_dataset.json"), encoding="utf-8"))


@pytest.fixture(scope="module")
def outputs(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    db = str(d / "fake.db")
    build_fake_db(db)
    m1 = run(db, str(d / "o1"))
    m2 = run(db, str(d / "o2"))
    return d, m1, m2


def test_reproducible_checksum(outputs):
    _, m1, m2 = outputs
    assert m1 == m2


def test_funnel_and_labels(outputs):
    d, _, _ = outputs
    s = json.load(open(d / "o1" / "summary.json", encoding="utf-8"))
    stages = {x["stage"]: x["removed"] for x in s["file_funnel"]}
    assert stages["language_excluded"] == 1 and stages["empty_diff"] == 1
    hk = pd.read_parquet(d / "o1" / "hunks.parquet")
    assert len(hk) == 90 and set(hk["label"]) == set(CWES)


def test_project_split_no_leak(outputs):
    d, _, _ = outputs
    s = json.load(open(d / "o1" / "summary.json", encoding="utf-8"))
    rep = s["leakage"]["split_project"]
    assert rep["shared_repo"] == 0 and rep["shared_cve"] == 0 and rep["n_test"] > 0
    assert s["leakage"]["split_random"]["shared_repo"] > 0
