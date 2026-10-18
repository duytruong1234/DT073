# Bước 2 – Chuẩn bị dữ liệu CVEfixes (chạy lại từ đầu được, có resume)
#   powershell -ExecutionPolicy Bypass -File scripts\run_step2.ps1
$ErrorActionPreference = "Stop"
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
& $py scripts/download_cvefixes.py      # tải + kiểm tra MD5 + ghi data/MANIFEST.json
if ($LASTEXITCODE -ne 0) { throw "Tải dữ liệu thất bại" }
& $py scripts/build_sqlite.py           # nạp SQL dump -> data/db/CVEfixes.db (nén cột mã)
if ($LASTEXITCODE -ne 0) { throw "Tạo CSDL thất bại" }
& $py scripts/data_report.py            # thống kê chất lượng dữ liệu ban đầu
