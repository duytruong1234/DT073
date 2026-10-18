"""Tiện ích dùng chung: cố định seed, đọc cấu hình, ghi metadata cho mỗi lần chạy."""
import datetime as dt
import json
import os
import platform
import random
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def set_seed(seed: int) -> None:
    """Cố định mọi nguồn ngẫu nhiên (Python, NumPy, PyTorch nếu có)."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


def load_config(path: str = os.path.join(ROOT, "configs", "base.yaml"), overrides: dict | None = None) -> dict:
    import yaml
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    for key, value in (overrides or {}).items():  # "split.main": "time"
        node = cfg
        *parents, last = key.split(".")
        for p in parents:
            node = node.setdefault(p, {})
        node[last] = value
    return cfg


def git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "-C", ROOT, "status", "--porcelain"], capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return None
        return out.stdout.strip() + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.TimeoutExpired):
        return None


def environment_info() -> dict:
    info = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil
        info["ram_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    except ImportError:
        pass
    try:
        info["git"] = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip()
    except OSError:
        info["git"] = None
    try:
        import torch
        info["cuda"] = torch.cuda.is_available()
        info["gpu"] = torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    except ImportError:
        info["cuda"] = None
    return info


def save_run_metadata(outdir: str, cfg: dict, seed: int, extra: dict | None = None) -> str:
    """Ghi config + seed + git commit + môi trường vào outdir/run_meta.json."""
    os.makedirs(outdir, exist_ok=True)
    meta = {
        "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
        "seed": seed,
        "git_commit": git_commit(),
        "environment": environment_info(),
        "config": cfg,
        **(extra or {}),
    }
    path = os.path.join(outdir, "run_meta.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    return path
