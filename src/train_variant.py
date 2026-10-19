"""CLI huấn luyện các mô hình Biến thể cải tiến (E4: patch, E5: patch + tree-sitter norm, E6: LinearSVC/LightGBM, E7: temporal)."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Chạy Biến thể cải tiến E5 (hoặc E4, E6, E7)")
    parser.add_argument("--exp", default="E5", choices=["E4", "E5", "E6", "E7"], help="Mã thí nghiệm biến thể")
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
