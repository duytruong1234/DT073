"""Ghi cấu hình phần cứng/phần mềm vào results/env.json (yêu cầu tái lập của đề).

    .venv\\Scripts\\python scripts/env_info.py
"""
import json
import os
import sys
from importlib import metadata

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from utils import environment_info, git_commit  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

KEY_PACKAGES = ["pandas", "pyarrow", "numpy", "scikit-learn", "lightgbm", "scipy", "statsmodels",
                "unidiff", "tree-sitter", "tree-sitter-language-pack", "datasketch", "pyyaml",
                "matplotlib", "seaborn", "pytest", "torch", "transformers"]


def main():
    info = environment_info()
    info["git_commit"] = git_commit()
    import sqlite3
    info["sqlite"] = sqlite3.sqlite_version
    pk = {}
    for p in KEY_PACKAGES:
        try:
            pk[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            pk[p] = None
    info["packages"] = pk
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", "env.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print(json.dumps(info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
