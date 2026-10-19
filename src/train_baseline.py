"""CLI huấn luyện mô hình Baseline chính (E3: TF-IDF trên before + LogisticRegression trên project split)."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Chạy Baseline chính E3 (hoặc E0..E2)")
    parser.add_argument("--exp", default="E3", choices=["E0", "E1", "E2", "E3"], help="Mã thí nghiệm baseline")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 123, 2024], help="Danh sách seed")
    args = parser.parse_args()
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "run_experiments.py"),
        "--exps",
        args.exp,
        "--seeds",
        *[str(s) for s in args.seeds],
    ]
    subprocess.run(cmd, check=True, cwd=str(ROOT))


if __name__ == "__main__":
    main()
