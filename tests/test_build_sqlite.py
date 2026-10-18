"""Test cho scripts/build_sqlite.py – chạy: python -m pytest tests/ -q  (hoặc python tests/test_build_sqlite.py)"""
import io
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from build_sqlite import iter_statements, table_of  # noqa: E402

# Mã nguồn có dấu ; cuối dòng, dấu nháy '' escape, CRLF và dòng trống – các ca dễ tách sai
CODE = "int main() {\r\n  char *s = 'x';\r\n  return 0;\r\n}\r\n"
DUMP = (
    "PRAGMA foreign_keys=OFF;\n"
    "BEGIN TRANSACTION;\n"
    'CREATE TABLE IF NOT EXISTS "file_change" (\n"id" TEXT,\n  "code" TEXT\n);\n'
    "INSERT INTO file_change VALUES('1','" + CODE.replace("'", "''") + "');\n"
    "INSERT INTO file_change VALUES('2','a;\n;\nb'';'';\n');\n"
    "INSERT INTO file_change VALUES('3',NULL);\n"
    "COMMIT;\n"
)


def _stmts(text):
    return list(iter_statements(io.StringIO(text, newline="")))


def test_split_count():
    stmts = _stmts(DUMP)
    assert len(stmts) == 7
    assert [table_of(s) for s in stmts].count("file_change") == 3


def test_roundtrip_preserves_code_exactly():
    con = sqlite3.connect(":memory:", isolation_level=None)
    for s in _stmts(DUMP):
        con.execute(s)
    rows = dict(con.execute("SELECT id, code FROM file_change"))
    assert rows["1"] == CODE              # giữ nguyên \r\n và dấu nháy
    assert rows["2"] == "a;\n;\nb';';\n"  # ; bên trong chuỗi không cắt câu lệnh
    assert rows["3"] is None


def test_truncated_dump_raises():
    try:
        _stmts("INSERT INTO t VALUES('chưa đóng chuỗi;\n")
    except ValueError:
        return
    raise AssertionError("Phải báo lỗi khi dump bị cắt giữa chừng")


FC_DUMP = (
    "BEGIN TRANSACTION;\n"
    'CREATE TABLE IF NOT EXISTS "file_change" (\n"file_change_id" TEXT,\n  "diff" TEXT,\n'
    '  "code_before" TEXT,\n  "code_after" TEXT,\n  "diff_parsed" TEXT\n);\n'
    + "".join(f"INSERT INTO file_change VALUES('{i}','@@ -1 +1 @@','{CODE.replace(chr(39), chr(39) * 2)}',NULL,'x');\n"
              for i in range(450))  # > FLUSH_EVERY để kiểm tra nhiều lô
    + 'CREATE TABLE IF NOT EXISTS "cve" (\n"cve_id" TEXT\n);\n'
    "INSERT INTO cve VALUES('CVE-1');\n"
    "COMMIT;\n"
)


def _load(compress, skip=()):
    from build_sqlite import DumpLoader
    from cvefixes_db import register_functions
    con = sqlite3.connect(":memory:", isolation_level=None)
    loader = DumpLoader(con, compress=compress, skip=skip)
    for s in _stmts(FC_DUMP):
        loader.execute(s)
    loader.finish()
    return register_functions(con), loader


def test_compressed_roundtrip():
    con, loader = _load(compress=True)
    assert con.execute("SELECT COUNT(*) FROM file_change").fetchone()[0] == 450
    assert con.execute("SELECT typeof(code_before), typeof(diff) FROM file_change LIMIT 1").fetchone() == ("blob", "text")
    vals = {r[0] for r in con.execute("SELECT unz(code_before) FROM file_change")}
    assert vals == {CODE}
    assert con.execute("SELECT code_after FROM file_change LIMIT 1").fetchone()[0] is None  # NULL giữ nguyên
    assert con.execute("SELECT COUNT(*) FROM cve").fetchone()[0] == 1
    assert loader.rows == {"file_change": 450, "cve": 1}


def test_uncompressed_and_skip():
    con, loader = _load(compress=False, skip=["cve"])
    assert con.execute("SELECT typeof(code_before) FROM file_change LIMIT 1").fetchone()[0] == "text"
    assert con.execute("SELECT COUNT(*) FROM cve").fetchone()[0] == 0
    assert loader.skipped == {"cve": 1}


def test_unsafe_statements_rejected(tmp_path):
    """Negative (trust boundary): dump độc hại không được ghi file/đổi cấu hình/sửa dữ liệu."""
    from build_sqlite import DumpLoader, UnsafeStatement
    con = sqlite3.connect(":memory:", isolation_level=None)
    loader = DumpLoader(con, compress=False)
    loader.execute('CREATE TABLE IF NOT EXISTS "t" (\n"a" TEXT\n);')
    evil = [
        f"ATTACH DATABASE '{tmp_path / 'pwn.db'}' AS x;",
        f"VACUUM INTO '{tmp_path / 'copy.db'}';",
        "PRAGMA writable_schema=ON;",
        "DROP TABLE t;",
        "UPDATE t SET a='x';",
        "INSERT INTO sqlite_master VALUES('table','x','x',0,'');",
        "INSERT INTO other VALUES('not created');",
        "SELECT load_extension('evil.dll');",
    ]
    for stmt in evil:
        try:
            loader.execute(stmt)
        except UnsafeStatement:
            continue
        raise AssertionError(f"Không chặn: {stmt}")
    assert not (tmp_path / "pwn.db").exists() and not (tmp_path / "copy.db").exists()
    loader.execute("INSERT INTO t VALUES('ok');")          # câu hợp lệ vẫn chạy
    assert con.execute("SELECT a FROM t").fetchone()[0] == "ok"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
