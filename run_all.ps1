<#
.SYNOPSIS
    Bước 8 – Script tái lập toàn bộ pipeline Đề tài DT073 (CVEfixes v1.0.8 -> Hunks -> CWE Classification).
.DESCRIPTION
    Chạy tuần tự các bước từ kiểm tra dữ liệu gốc, dựng SQLite DB (nếu chưa có), chạy kiểm thử pytest,
    dựng tập dữ liệu tái lập (hunks.parquet + splits.parquet), huấn luyện ma trận thí nghiệm E0..E7 (3 seed),
    đánh giá thống kê (Bootstrap CI 95%, McNemar, phân tích lỗi) và chạy demo dự đoán Top-3 CWE.
#>
param(
    [switch]$RebuildDb = $false,
    [switch]$RunOnlineCheck = $false
)

$ErrorActionPreference = "Stop"
$env:PYTHONUNBUFFERED = "1"
$Py = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $Py)) {
    Write-Error "Chưa tìm thấy môi trường ảo tại $Py. Hãy chạy: python -m venv .venv; .\.venv\Scripts\pip install -r requirements-lock.txt"
}

Write-Host "=== [1/7] Kiểm tra tệp nén CVEfixes v1.0.8 & SQLite DB ===" -ForegroundColor Cyan
& $Py scripts/download_cvefixes.py
if ($RebuildDb -or -not (Test-Path "data/db/CVEfixes.db")) {
    & $Py scripts/build_sqlite.py
}
& $Py scripts/data_report.py

Write-Host "=== [2/7] Chạy bộ kiểm thử tự động (Unit / Integration / Negative Tests) ===" -ForegroundColor Cyan
& $Py -m pytest -q

Write-Host "=== [3/7] Phân tích khám phá dữ liệu (EDA 2 tầng) ===" -ForegroundColor Cyan
& $Py scripts/eda.py --stage all

Write-Host "=== [4/7] Xây dựng tập dữ liệu hunk tái lập (Bước 5a-5e) ===" -ForegroundColor Cyan
& $Py scripts/build_dataset.py
if ($RunOnlineCheck) {
    & $Py scripts/verify_commits_online.py --n 100 --seed 42
}

Write-Host "=== [5/7] Huấn luyện ma trận thí nghiệm E0..E7 x 3 seed (Bước 5f & 6) ===" -ForegroundColor Cyan
& $Py scripts/run_experiments.py

Write-Host "=== [6/7] Đánh giá thống kê, Bootstrap CI 95%, McNemar & Phân tích lỗi (Bước 7) ===" -ForegroundColor Cyan
& $Py scripts/evaluate_all.py
& $Py scripts/label_audit.py heuristic

Write-Host "=== [7/7] Chạy Demo dự đoán Top-3 CWE từ bản vá (Bước 8) ===" -ForegroundColor Cyan
& $Py scripts/demo_predict.py

Write-Host "=== HOÀN TẤT TOÀN BỘ PIPELINE DT073 ===" -ForegroundColor Green
