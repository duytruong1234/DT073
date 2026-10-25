"""Bước 2b: Chuyển SQL dump của CVEfixes thành CSDL SQLite (CVEfixes.db).

Đọc THẲNG từ file zip -> gzip -> SQLite theo kiểu streaming, KHÔNG giải nén file .sql
ra ổ đĩa. Tương đương lệnh gốc trong INSTALL.md của CVEfixes:
    gzcat Data/CVEfixes_v1.0.8.sql.gz | sqlite3 Data/CVEfixes.db

Khác biệt duy nhất (mặc định, có thể tắt bằng --no-compress): các cột mã nguồn rất lớn
(file_change.code_before / code_after / diff_parsed, method_change.code) được lưu dưới
dạng BLOB nén zlib – KHÔNG MẤT DỮ LIỆU. Lý do: 2 cột code_before/code_after chiếm ~90%
dung lượng; DB không nén ước tính ~65 GB, nén còn khoảng 15–20 GB.
Đọc lại bằng hàm unz() trong src/cvefixes_db.py.

Cách chạy:
    python scripts/build_sqlite.py
    python scripts/build_sqlite.py --no-compress               # DB nguyên bản (cần ~65 GB)
    python scripts/build_sqlite.py --skip-tables method_change # bỏ bảng nếu cần
"""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import zipfile

for _s in (sys.stdout, sys.stderr):  # tránh lỗi in tiếng Việt khi output bị chuyển hướng (cp1252)
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

ZIP_PATH = os.path.join("data", "raw", "CVEfixes_v1.0.8.zip")
PREFIX = "CVEfixes_v1.0.8/"
SQL_MEMBER = PREFIX + "Data/CVEfixes_v1.0.8.sql.gz"
EXTRACT_DIR = os.path.join("data", "raw", "CVEfixes_v1.0.8")
DB_PATH = os.path.join("data", "db", "CVEfixes.db")
STATS_PATH = os.path.join("data", "db_stats.json")
MANIFEST = os.path.join("data", "MANIFEST.json")

# Cột được nén zlib (lossless)
COMPRESS = {
    "file_change": {"code_before", "code_after", "diff_parsed"},
    "method_change": {"code"},
}
FLUSH_EVERY = 200  # số dòng gom lại trước khi nén & chuyển sang bảng chính

# Chỉ mục tạo sau khi nạp (bảng -> cột)
INDEXES = {
    "fixes": ("hash", "repo_url"),
    "commits": ("hash", "repo_url"),
    "file_change": ("hash",),
    "method_change": ("file_change_id",),
    "cwe_classification": ("cve_id",),
    "cve": ("cve_id",),
}

# Số liệu công bố trên Zenodo cho v1.0.8 (để đối chiếu sau khi nạp)
# Lưu ý: README CVEfixes ghi "138974 functions" = số HÀM; bảng method_change lưu mỗi phiên bản hàm thành 1 dòng
# (before_change = True/False) nên số dòng thực tế là 277.948 – KHÔNG phải nạp trùng (mọi method_change_id đều khác nhau).
EXPECTED = {"commits": 12107, "cve": 11873, "file_change": 51342, "method_change": 138974}

RE_CREATE = re.compile(r'^CREATE TABLE (?:IF NOT EXISTS )?"?([^"\s(]+)"?')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from cvefixes_db import zc, register_functions  # noqa: E402


class CountingReader(io.RawIOBase):
    """Bọc stream để đếm số byte nén đã đọc -> hiển thị tiến độ."""

    def __init__(self, raw):
        self.raw, self.count = raw, 0

    def readable(self):
        return True

    def readinto(self, b):
        n = self.raw.readinto(b)
        self.count += n or 0
        return n


def extract_small_files(zf):
    """Giải nén mọi thứ TRỪ file .sql.gz (tài liệu, CWE xml, NVD json, log)."""
    for info in zf.infolist():
        if info.filename == SQL_MEMBER or info.is_dir():
            continue
        target = os.path.join(EXTRACT_DIR, info.filename[len(PREFIX):])
        if os.path.exists(target) and os.path.getsize(target) == info.file_size:
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        print(f"  giải nén: {target}")


def iter_statements(text_stream):
    """Tách dump thành từng câu lệnh SQL.

    Theo dõi trạng thái chuỗi '...' bằng cách đếm dấu nháy đơn trên mỗi dòng
    (dấu '' escape làm trạng thái đổi 2 lần nên không ảnh hưởng). Câu lệnh kết thúc
    khi không ở trong chuỗi và dòng kết thúc bằng ';'. Xác nhận lại bằng
    sqlite3.complete_statement (chỉ gọi 1 lần/câu -> nhanh).
    """
    buf, in_str = [], False
    for line in text_stream:
        buf.append(line)
        if line.count("'") % 2:
            in_str = not in_str
        if not in_str and line.rstrip().endswith(";"):
            stmt = "".join(buf)
            if sqlite3.complete_statement(stmt):
                yield stmt
                buf = []
    if buf and "".join(buf).strip():
        raise ValueError("Dump kết thúc giữa chừng một câu lệnh – file có thể bị hỏng.")


def table_of(stmt):
    if stmt.startswith("INSERT INTO "):
        return stmt[12:stmt.find(" ", 12)].strip('"')
    return None


# Trust boundary: dump tải từ Internet là KHÔNG tin cậy -> chỉ cho phép các câu lệnh mà lệnh `.dump`
# của SQLite sinh ra. Chặn ATTACH/DETACH (ghi file tùy ý), VACUUM INTO, PRAGMA khác, DROP, UPDATE...
ALLOWED_STMT = re.compile(
    r"^\s*(PRAGMA\s+foreign_keys\s*=\s*(OFF|ON)\s*;|BEGIN(\s+TRANSACTION)?\s*;|COMMIT\s*;|END\s+TRANSACTION\s*;|"
    r"CREATE\s+TABLE\s|CREATE\s+(UNIQUE\s+)?INDEX\s|INSERT\s+INTO\s|ANALYZE\s|DELETE\s+FROM\s+sqlite_sequence\s*;)",
    re.I)
SYSTEM_TABLES = {"sqlite_sequence", "sqlite_stat1", "sqlite_stat4"}


class UnsafeStatement(ValueError):
    pass


def check_allowed(stmt: str, created: set) -> None:
    if not ALLOWED_STMT.match(stmt):
        raise UnsafeStatement(f"Câu lệnh không được phép trong dump: {stmt[:80]!r}")
    t = table_of(stmt.lstrip())
    if t is not None and t not in created and t not in SYSTEM_TABLES:
        raise UnsafeStatement(f"INSERT vào bảng không được tạo trong dump: {t!r}")


class DumpLoader:
    """Thực thi dump vào `con`; với bảng cần nén thì INSERT vào bảng tạm rồi nén theo lô."""

    def __init__(self, con, compress=True, skip=()):
        self.con, self.skip = con, set(skip)
        self.compress = COMPRESS if compress else {}
        self.staged = {}     # bảng -> câu lệnh chuyển dữ liệu (đã nén) sang bảng chính
        self.pending = {}    # bảng -> số dòng đang chờ trong bảng tạm
        self.rows, self.skipped = {}, {}
        self.created = set()  # bảng được CREATE trong dump – chỉ cho INSERT vào các bảng này
        register_functions(con)

    def _setup_stage(self, table):
        cols = [c[1] for c in self.con.execute(f'PRAGMA main.table_info("{table}")')]
        sel = ", ".join(f'zc("{c}")' if c in self.compress[table] else f'"{c}"' for c in cols)
        self.con.execute(f'CREATE TEMP TABLE "stage_{table}" AS SELECT * FROM main."{table}" WHERE 0')
        self.staged[table] = (f'INSERT INTO main."{table}" SELECT {sel} FROM temp."stage_{table}"',
                              f'DELETE FROM temp."stage_{table}"')
        self.pending[table] = 0

    def flush(self, table=None):
        for t in [table] if table else list(self.staged):
            if self.pending.get(t):
                move, clear = self.staged[t]
                self.con.execute(move)
                self.con.execute(clear)
                self.pending[t] = 0

    def execute(self, stmt):
        check_allowed(stmt, self.created)
        t = table_of(stmt)
        if t is not None:
            if t in self.skip:
                self.skipped[t] = self.skipped.get(t, 0) + 1
                return t
            self.rows[t] = self.rows.get(t, 0) + 1
            if t in self.staged:
                self.con.execute(f'INSERT INTO temp."stage_{t}"' + stmt[stmt.find(" VALUES"):])
                self.pending[t] += 1
                if self.pending[t] >= FLUSH_EVERY:
                    self.flush(t)
                return t
        else:
            self.flush()  # trước COMMIT/CREATE/... đẩy hết dữ liệu đang chờ
        self.con.execute(stmt)
        m = RE_CREATE.match(stmt)
        if m:
            self.created.add(m.group(1))
            if m.group(1) in self.compress:
                self._setup_stage(m.group(1))
        return t

    def finish(self):
        self.flush()
        if self.con.in_transaction:
            self.con.execute("COMMIT")
        for t in self.staged:
            self.con.execute(f'DROP TABLE IF EXISTS temp."stage_{t}"')
        # Chỉ mục trên các khóa nối (dump gốc không có) -> truy vấn ở các bước sau nhanh hơn nhiều
        existing = {r[0] for r in self.con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, cols in INDEXES.items():
            have = {r[1] for r in self.con.execute(f'PRAGMA table_info("{table}")')} if table in existing else set()
            if set(cols) <= have:
                self.con.execute(f'CREATE INDEX IF NOT EXISTS "ix_{table}_{"_".join(cols)}" '
                                 f'ON "{table}" ({", ".join(cols)})')
        self.con.execute("CREATE TABLE IF NOT EXISTS _build_info (key TEXT PRIMARY KEY, value TEXT)")
        self.con.execute("INSERT OR REPLACE INTO _build_info VALUES ('compressed_columns', ?)",
                         (json.dumps({k: sorted(v) for k, v in self.compress.items()}),))
        self.con.execute("INSERT OR REPLACE INTO _build_info VALUES ('compression', ?)",
                         ("zlib (đọc bằng unz() trong src/cvefixes_db.py)" if self.compress else "none",))


def sha256(path, chunk=8 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tables", nargs="*", default=[], help="Bỏ INSERT của các bảng này")
    ap.add_argument("--no-compress", action="store_true", help="Không nén cột mã nguồn (DB ~65 GB)")
    ap.add_argument("--force", action="store_true", help="Ghi đè DB đã có")
    ap.add_argument("--no-hash", action="store_true", help="Không tính SHA-256 của DB (nhanh hơn)")
    args = ap.parse_args()

    if not os.path.exists(ZIP_PATH):
        sys.exit(f"Không thấy {ZIP_PATH}. Hãy chạy scripts/download_cvefixes.py trước.")
    if os.path.exists(DB_PATH) and not args.force:
        sys.exit(f"{DB_PATH} đã tồn tại. Dùng --force để tạo lại.")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    partial = DB_PATH + ".partial"
    if os.path.exists(partial):
        os.remove(partial)

    zf = zipfile.ZipFile(ZIP_PATH)
    print("[1/4] Giải nén tài liệu & file phụ ...")
    extract_small_files(zf)

    total_gz = zf.getinfo(SQL_MEMBER).compress_size
    free_gb = shutil.disk_usage(os.path.dirname(DB_PATH)).free / 1e9
    print(f"[2/4] Nạp SQL dump vào SQLite (nén cột mã: {not args.no_compress}; ổ trống: {free_gb:.1f} GB) ...")

    con = sqlite3.connect(partial, isolation_level=None)  # autocommit: dùng BEGIN/COMMIT của dump
    # Tăng tốc nạp 1 lần: tắt journal/fsync (nếu lỗi giữa chừng thì xóa .partial và chạy lại)
    for p in ("journal_mode=OFF", "synchronous=OFF", "temp_store=MEMORY",
              "cache_size=-1048576", "locking_mode=EXCLUSIVE"):
        con.execute(f"PRAGMA {p}")
    loader = DumpLoader(con, compress=not args.no_compress, skip=args.skip_tables)

    counter = CountingReader(zf.open(SQL_MEMBER))
    gz = gzip.GzipFile(fileobj=io.BufferedReader(counter, 1 << 20))
    text = io.TextIOWrapper(gz, encoding="utf-8", newline="")  # newline="" giữ nguyên \r\n trong mã nguồn

    t0, last, n_stmt = time.time(), 0.0, 0
    try:
        for stmt in iter_statements(text):
            t = loader.execute(stmt)
            n_stmt += 1
            now = time.time()
            if now - last > 5:
                last = now
                frac = counter.count / total_gz
                eta = (now - t0) / max(frac, 1e-9) * (1 - frac)
                db_gb = os.path.getsize(partial) / 1e9
                free_gb = shutil.disk_usage(os.path.dirname(DB_PATH)).free / 1e9
                sys.stdout.write(f"\r  {frac:6.1%} | DB {db_gb:6.2f} GB | trống {free_gb:6.1f} GB | "
                                 f"còn ~{eta / 60:5.0f} phút | bảng: {t or '-':15s}")
                sys.stdout.flush()
                if free_gb < 2:
                    raise RuntimeError("Ổ đĩa sắp đầy (< 2 GB). Dừng để tránh hỏng dữ liệu.")
        loader.finish()
    except Exception:
        con.close()
        print("\nLỖI – đã dừng. File dở dang:", partial)
        raise
    print(f"\n  Xong {n_stmt:,} câu lệnh trong {(time.time() - t0) / 60:.1f} phút.")

    print("[3/4] Kiểm tra CSDL ...")
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    counts = {t: con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables}
    schema = {t: [c[1] for c in con.execute(f'PRAGMA table_info("{t}")')] for t in tables}
    if not args.no_compress and counts.get("file_change"):  # thử giải nén vài dòng
        for (v,) in con.execute("SELECT unz(code_before) FROM file_change ORDER BY random() LIMIT 50"):
            assert v is None or isinstance(v, str)
    con.close()
    os.replace(partial, DB_PATH)

    print(f"  {'bảng':20s} {'số dòng':>12s} {'kỳ vọng':>10s}")
    for t in tables:
        print(f"  {t:20s} {counts[t]:>12,} {EXPECTED.get(t, ''):>10}")

    stats = {
        "built_at": dt.datetime.now().isoformat(timespec="seconds"),
        "db_path": DB_PATH,
        "db_size_bytes": os.path.getsize(DB_PATH),
        "compressed_columns": {} if args.no_compress else {k: sorted(v) for k, v in COMPRESS.items()},
        "skipped_rows": loader.skipped,
        "row_counts": counts,
        "expected_from_zenodo": EXPECTED,
        "schema": schema,
    }
    if not args.no_hash:
        print("[4/4] Tính SHA-256 của CVEfixes.db (vài phút) ...")
        stats["db_sha256"] = sha256(DB_PATH)
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    if os.path.exists(MANIFEST):
        with open(MANIFEST, encoding="utf-8") as f:
            man = json.load(f)
        man.setdefault("derived", {})["CVEfixes.db"] = {
            "size": stats["db_size_bytes"], "sha256": stats.get("db_sha256"),
            "built_by": "scripts/build_sqlite.py",
            "compressed_columns": stats["compressed_columns"], "skipped_rows": loader.skipped}
        with open(MANIFEST, "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=2)
    print(f"OK. DB: {DB_PATH} | thống kê: {STATS_PATH}")


if __name__ == "__main__":
    main()
