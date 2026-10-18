"""Bước 5b (online) – Kiểm tra mẫu ngẫu nhiên commit của CVEfixes còn tồn tại trên repo gốc và
danh sách file thay đổi có khớp CVEfixes không. Chỉ fetch lịch sử git (không checkout, không chạy mã).

    .venv\\Scripts\\python scripts/verify_commits_online.py --n 100 --seed 42
    (--db data/interim/sample.db để thử trên DB mẫu)
"""
import argparse
import json
import os
import random
import sys
import time

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from cvefixes_db import connect  # noqa: E402
from utils import load_config  # noqa: E402
from validate import verify_commit_online  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=None)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--exclude-large", action="store_true", help="Bỏ repo rất lớn (linux…) để chạy nhanh")
    ap.add_argument("--out", default=os.path.join("results", "validate_online.json"))
    args = ap.parse_args()
    cfg = load_config()
    con = connect(args.db or cfg["paths"]["db"])
    rows = con.execute("""SELECT c.hash, c.repo_url FROM commits c
                          WHERE c.hash IN (SELECT hash FROM file_change) ORDER BY c.hash, c.repo_url""").fetchall()
    if args.exclude_large:
        big = ("torvalds/linux", "tensorflow/tensorflow", "chromium", "mozilla", "LibreOffice", "php/php-src")
        rows = [r for r in rows if not any(b in r[1] for b in big)]
    rng = random.Random(args.seed)
    sample = rng.sample(rows, min(args.n, len(rows)))
    results, t0 = [], time.time()
    for i, (sha, url) in enumerate(sample, 1):
        db_files = sorted({(p or "").replace("\\", "/") for (p,) in con.execute(
            "SELECT COALESCE(NULLIF(new_path,'None'), old_path) FROM file_change WHERE hash=?", (sha,))})
        r = verify_commit_online(url, sha)
        gh = set(r["files"])
        match = r["exists"] and set(db_files) <= gh
        results.append({"hash": sha, "repo_url": url, "exists": r["exists"], "error": r["error"],
                        "db_files": len(db_files), "git_files": len(gh), "db_files_subset_of_git": match})
        print(f"[{i}/{len(sample)}] {'OK ' if match else 'ERR' if not r['exists'] else 'DIF'} {url} {sha[:10]} {r['error'] or ''}")
    n = len(results)
    summary = {
        "n": n, "seed": args.seed, "seconds": round(time.time() - t0, 1),
        "exists_rate": round(sum(r["exists"] for r in results) / n, 4) if n else None,
        "file_match_rate": round(sum(r["db_files_subset_of_git"] for r in results) / n, 4) if n else None,
        "errors": {e: sum(1 for r in results if r["error"] == e) for e in {r["error"] for r in results if r["error"]}},
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "results": results}, f, ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
