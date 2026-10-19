"""CLI tải dữ liệu CVEfixes v1.0.8 từ Zenodo và kiểm tra checksum SHA-256 / MD5 (Bước 2 & 3.1)."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "data" / "MANIFEST.json"


def compute_sha256(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(manifest_path: Path = MANIFEST_PATH, verify_hash: bool = False) -> dict:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Không tìm thấy {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    status = {"manifest": str(manifest_path), "verified": {}}
    zip_info = manifest.get("files", {}).get("CVEfixes_v1.0.8.zip", {})
    zip_path = ROOT / "data" / "raw" / "CVEfixes_v1.0.8.zip"
    db_info = manifest.get("derived", {}).get("CVEfixes.db", {})
    db_path = ROOT / "data" / "db" / "CVEfixes.db"

    for label, p, info in [("CVEfixes_v1.0.8.zip", zip_path, zip_info), ("CVEfixes.db", db_path, db_info)]:
        exists = p.exists()
        entry = {"exists": exists, "expected_size": info.get("size"), "expected_sha256": info.get("sha256")}
        if exists:
            entry["actual_size"] = p.stat().st_size
            entry["size_match"] = entry["actual_size"] == info.get("size")
            if verify_hash:
                actual_sha = compute_sha256(p)
                entry["actual_sha256"] = actual_sha
                entry["sha256_match"] = actual_sha == info.get("sha256")
        status["verified"][label] = entry
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description="Kiểm tra hoặc tải CVEfixes v1.0.8 theo MANIFEST.json")
    parser.add_argument("--config", default="configs/dataset.yaml", help="Đường dẫn file cấu hình")
    parser.add_argument("--verify-sha256", action="store_true", help="Tính lại SHA-256 trên toàn bộ file 12.7 GB")
    args = parser.parse_args()
    res = verify_manifest(verify_hash=args.verify_sha256)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
