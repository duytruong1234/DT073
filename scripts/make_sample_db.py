"""Tạo CSDL MẪU từ phần đầu file zip (kể cả khi zip chưa tải xong) – chỉ để phát triển/kiểm thử code.

Phần đầu SQL dump chứa bảng fixes, commits và một phần file_change (chưa có nhãn CWE).
File zip chỉ được MỞ ĐỌC, không ảnh hưởng tiến trình đang tải.

    .venv\\Scripts\\python scripts/make_sample_db.py --mb 120
"""
import argparse
import io
import os
import sqlite3
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_sqlite import ZIP_PATH, SQL_MEMBER, DumpLoader, iter_statements  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Vị trí local header của Data/CVEfixes_v1.0.8.sql.gz trong zip (đọc từ central directory trên Zenodo)
SQL_HEADER_OFFSET = 1_485_686
OUT = os.path.join("data", "interim", "sample.db")


class PartialMember(io.RawIOBase):
    """Đọc thành viên deflate trong zip -> giải nén gzip, dừng sau `limit` byte nén."""

    def __init__(self, path, offset, limit):
        self.f = open(path, "rb")
        self.f.seek(offset)
        h = self.f.read(30)
        if h[:4] != b"PK\x03\x04":
            raise ValueError("Sai vị trí local header trong zip")
        n, m = struct.unpack("<HH", h[26:30])
        name = self.f.read(n).decode()
        if name != SQL_MEMBER:
            raise ValueError(f"Thành viên không khớp: {name}")
        self.f.seek(m, 1)
        self.inflate, self.gunzip = zlib.decompressobj(-15), zlib.decompressobj(31)
        self.buf, self.read_in, self.limit = b"", 0, limit

    def readable(self):
        return True

    def readinto(self, b):
        while not self.buf:
            if self.read_in >= self.limit:
                return 0
            chunk = self.f.read(1 << 20)
            if not chunk:
                return 0
            self.read_in += len(chunk)
            self.buf = self.gunzip.decompress(self.inflate.decompress(chunk))
        n = min(len(b), len(self.buf))
        b[:n], self.buf = self.buf[:n], self.buf[n:]
        return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=120, help="Số MB nén đọc từ đầu dump")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    if os.path.exists(args.out):
        os.remove(args.out)
    con = sqlite3.connect(args.out, isolation_level=None)
    for p in ("journal_mode=OFF", "synchronous=OFF", "temp_store=MEMORY"):
        con.execute(f"PRAGMA {p}")
    loader = DumpLoader(con)
    src = PartialMember(ZIP_PATH, SQL_HEADER_OFFSET, args.mb << 20)
    text = io.TextIOWrapper(io.BufferedReader(src, 1 << 20), encoding="utf-8", newline="")
    try:
        for stmt in iter_statements(text):
            loader.execute(stmt)
    except ValueError:
        pass  # mẫu bị cắt giữa một câu lệnh – bình thường
    loader.finish()
    con.close()
    print(f"OK {args.out}: {loader.rows}")


if __name__ == "__main__":
    main()
