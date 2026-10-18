"""Kiểm tra tiện ích tái lập: seed cho kết quả lặp lại, config override đúng, metadata đủ trường."""
import json
import os
import random

from utils import load_config, save_run_metadata, set_seed


def test_seed_reproducible():
    import numpy as np
    set_seed(42)
    a = (random.random(), np.random.rand(3).tolist())
    set_seed(42)
    b = (random.random(), np.random.rand(3).tolist())
    assert a == b


def test_config_loads_and_overrides():
    cfg = load_config(overrides={"split.main": "time", "dataset.top_k_cwe": 20})
    assert len(cfg["seeds"]) >= 3
    assert cfg["split"]["main"] == "time"
    assert cfg["dataset"]["top_k_cwe"] == 20


def test_run_metadata(tmp_path):
    p = save_run_metadata(str(tmp_path), {"a": 1}, seed=123)
    meta = json.load(open(p, encoding="utf-8"))
    for k in ("timestamp", "seed", "git_commit", "environment", "config"):
        assert k in meta
    assert meta["seed"] == 123 and os.path.basename(p) == "run_meta.json"
