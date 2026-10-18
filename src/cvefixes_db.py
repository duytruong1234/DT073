"""Tiện ích đọc CVEfixes.db (bản build bởi scripts/build_sqlite.py).

Các cột mã nguồn lớn được lưu dạng BLOB nén zlib. Dùng `connect()` để có sẵn hàm SQL `unz()`:

    from cvefixes_db import connect
    con = connect()
    con.execute("SELECT filename, unz(code_before) FROM file_change LIMIT 1").fetchone()

Hoặc trong Python: `unz(value)` với giá trị đọc ra.
"""
import os
import sqlite3
import zlib

DEFAULT_DB = os.path.join("data", "db", "CVEfixes.db")


def zc(value):
    """Nén chuỗi -> BLOB zlib. NULL giữ nguyên NULL."""
    if value is None:
        return None
    if isinstance(value, str):
        value = value.encode("utf-8")
    return zlib.compress(value, 6)


def unz(value):
    """Giải nén BLOB zlib -> str. Giá trị không nén (str/số/NULL) trả về nguyên trạng."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return zlib.decompress(value).decode("utf-8")
    return value


def register_functions(con):
    con.create_function("zc", 1, zc, deterministic=True)
    con.create_function("unz", 1, unz, deterministic=True)
    return con


def connect(path=DEFAULT_DB, readonly=True):
    if readonly:
        uri = "file:" + os.path.abspath(path).replace("\\", "/") + "?mode=ro"
        con = sqlite3.connect(uri, uri=True)
    else:
        con = sqlite3.connect(path)
    return register_functions(con)
