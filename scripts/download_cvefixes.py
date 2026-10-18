"""Tải CVEfixes v1.0.8 từ Zenodo, hỗ trợ tải tiếp (resume), kiểm tra MD5 và ghi MANIFEST.

Cách chạy:
    python scripts/download_cvefixes.py
"""
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.request

for _s in (sys.stdout, sys.stderr):  # tránh lỗi in tiếng Việt khi output bị chuyển hướng (cp1252)
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

RECORD_ID = "13118970"  # Zenodo record của CVEfixes v1.0.8 (concept DOI 10.5281/zenodo.4476563)
FILE_NAME = "CVEfixes_v1.0.8.zip"
URL = f"https://zenodo.org/api/records/{RECORD_ID}/files/{FILE_NAME}/content"
EXPECTED_SIZE = 12_708_711_268
EXPECTED_MD5 = "4586a358977acfa4c60b1a2cdd096221"

RAW_DIR = os.path.join("data", "raw")
OUT = os.path.join(RAW_DIR, FILE_NAME)
MANIFEST = os.path.join("data", "MANIFEST.json")
CHUNK = 8 * 1024 * 1024


def download():
    os.makedirs(RAW_DIR, exist_ok=True)
    have = os.path.getsize(OUT) if os.path.exists(OUT) else 0
    if have == EXPECTED_SIZE:
        print("Đã tải đủ, bỏ qua bước tải.")
        return
    req = urllib.request.Request(URL, headers={"Range": f"bytes={have}-"} if have else {})
    with urllib.request.urlopen(req, timeout=120) as r:
        if have and r.status != 206:  # server bỏ qua Range -> tải lại từ đầu, không nối sai
            print("Server không hỗ trợ tải tiếp, tải lại từ đầu.")
            have = 0
        print(f"Bắt đầu từ {have / 1e9:.2f} GB")
        with open(OUT, "ab" if have else "wb") as f:
            done = have
            while True:
                buf = r.read(CHUNK)
                if not buf:
                    break
                f.write(buf)
                done += len(buf)
                sys.stdout.write(f"\r{done / 1e9:6.2f} / {EXPECTED_SIZE / 1e9:.2f} GB")
                sys.stdout.flush()
    print()


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(CHUNK), b""):
            h.update(buf)
    return h.hexdigest()


def main():
    download()
    size = os.path.getsize(OUT)
    if size != EXPECTED_SIZE:
        sys.exit(f"Sai kích thước: {size} != {EXPECTED_SIZE}. Chạy lại script để tải tiếp.")
    print("Đang tính MD5 và SHA-256 (mất vài phút)...")
    md5, sha256 = file_hash(OUT, "md5"), file_hash(OUT, "sha256")
    if md5 != EXPECTED_MD5:
        sys.exit(f"MD5 không khớp: {md5} != {EXPECTED_MD5}. File hỏng, hãy xóa và tải lại.")
    manifest = {
        "dataset": "CVEfixes",
        "version": "v1.0.8",
        "coverage": "CVE công bố đến 23/07/2024",
        "doi": "10.5281/zenodo.4476563",
        "zenodo_record": RECORD_ID,
        "url": URL,
        "license": "CC BY 4.0 (dữ liệu), MIT (mã nguồn thu thập)",
        "citation": "Bhandari, Naseer, Moonen. CVEfixes. PROMISE '21. doi:10.1145/3475960.3475985",
        "downloaded_at": dt.datetime.now().isoformat(timespec="seconds"),
        "files": {FILE_NAME: {"size": size, "md5": md5, "sha256": sha256}},
    }
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"OK. MD5 khớp. Đã ghi {MANIFEST}")


if __name__ == "__main__":
    main()
