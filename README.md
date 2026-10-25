# DT073 – Trích cặp mã trước/sau sửa lỗi (Hunks) từ CVEfixes và Phân loại CWE

Gói tái lập hoàn chỉnh cho đề tài **DT073**: Xây dựng pipeline xử lý dữ liệu có kiểm chứng từ bộ dữ liệu công khai **CVEfixes v1.0.8**, trích xuất cặp mã nguồn trước/sau sửa lỗi ở mức hunk, khử trùng lặp 3 mức, chia tập chống rò rỉ dữ liệu (`project split` & `time split`), huấn luyện – đánh giá phân loại đa lớp CWE và đối chiếu định lượng với các nhận định của bài báo khảo sát nền tảng:

- **Bài báo nền tảng:** C. Liang, Q. Wei, J. Du, Y. Wang, Z. Jiang, *"Survey of source code vulnerability analysis based on deep learning"*, Computers & Security, Vol. 148, 2025, 104098, doi:`10.1016/j.cose.2024.104098`.
- **Bộ dữ liệu gốc:** G. Bhandari, A. Naseer, L. Moonen, *"CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software"*, PROMISE '21, doi:`10.1145/3475960.3475985` – phát hành trên Zenodo (`v1.0.8`, doi:`10.5281/zenodo.13118970`) theo giấy phép **CC BY 4.0**.

---

## 1. Yêu cầu Hệ thống

| Thành phần | Cấu hình tối thiểu / Đã kiểm thử (`results/env.json`) |
|---|---|
| **Hệ điều hành** | Windows 10/11 (PowerShell 5.1+ / PowerShell 7) |
| **Python** | Python `3.12.10` |
| **Git** | Git $\ge 2.40$ (dùng để kiểm tra trực tuyến lịch sử commit ở chế độ `--bare`) |
| **Ổ đĩa trống** | $\ge 30$ GB (`CVEfixes_v1.0.8.zip`: 12,71 GB + `CVEfixes.db` nén cột mã lossless: 13,54 GB + dữ liệu xử lý: ~35 MB) |
| **RAM** | $\ge 8$ GB (máy kiểm thử: Intel 12 luồng CPU, 16,89 GB RAM, **không cần GPU**) |

---

## 2. Cài đặt Môi trường Tái lập (Bước 3)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/env_info.py
```

---

## 3. Chạy Toàn bộ Pipeline bằng 1 Lệnh (Bước 2 → Bước 8)

```powershell
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

Hoặc chạy từng bước độc lập:

```powershell
# Bước 2: Tải CVEfixes v1.0.8 (hỗ trợ resume, kiểm tra MD5/SHA-256) & dựng SQLite DB nén lossless
.\.venv\Scripts\python.exe scripts/download_cvefixes.py
.\.venv\Scripts\python.exe scripts/build_sqlite.py
.\.venv\Scripts\python.exe scripts/data_report.py

# Bước 4: Phân tích khám phá dữ liệu 2 tầng (EDA) theo quy tắc tất định
.\.venv\Scripts\python.exe scripts/eda.py --stage all

# Bước 5: Xây dựng tập dữ liệu hunk tái lập (metadata -> validate -> hunks -> normalize -> dedup -> split)
.\.venv\Scripts\python.exe scripts/build_dataset.py
.\.venv\Scripts\python.exe scripts/verify_commits_online.py --n 100 --seed 42
.\.venv\Scripts\python.exe scripts/label_audit.py sample --n 200 --seed 42
.\.venv\Scripts\python.exe scripts/label_audit.py heuristic

# Bước 6: Chạy ma trận thí nghiệm có kiểm soát (E0..E7 × 3 seed = 24 lần chạy)
.\.venv\Scripts\python.exe scripts/run_experiments.py

# Bước 7: Đánh giá thống kê (Bootstrap CI 95% 1.000 lần, McNemar test, ma trận nhầm lẫn, 50 mẫu lỗi)
.\.venv\Scripts\python.exe scripts/evaluate_all.py

# Bước 8: Chạy Demo dự đoán Top-3 CWE từ bản vá unified diff
.\.venv\Scripts\python.exe scripts/demo_predict.py
```

### Kiểm tra nhanh kết quả KHÔNG cần tải 12,7 GB dữ liệu

Dự đoán thô của cả 24 lần chạy được commit tại `results/experiments/<Exp>/seed_<s>/predictions.csv`
(cột `hunk_id, y_true, y_pred, top3_preds`; không chứa mã nguồn hay thông tin cá nhân). Lệnh sau tính lại
Macro-F1 / Top-3 của từng lần chạy, so với `metrics.json` và chạy kiểm định McNemar chính xác E5 vs E3:

```powershell
.\.venv\Scripts\python.exe scripts/verify_metrics_from_predictions.py
```

---

## 4. Tóm tắt Kết quả Thực nghiệm Chính

### 4.1. Các chỉ số Chất lượng Bộ dữ liệu (`data/processed/summary.json`)
- **Coverage (D3)**: Từ `51.342` bản ghi `file_change` → lọc 9 ngôn ngữ (`PHP, C, JavaScript, Python, Java, TypeScript, C++, Go, Ruby`), bỏ file `ADD/DELETE`, bỏ tangled commit ($>9$ file mã nguồn) và file $>500$ dòng đổi → còn **18.580 file hợp lệ (36,19%)** → tách được **40.254 hunk hợp lệ** → lọc đại diện gần trùng và nhãn đơn thuộc Top-17 CWE ($\ge 500$ hunk/lớp) → **17.642 hunk mô hình hóa** (`19.553` hunk nếu không khử trùng lặp).
- **Duplicate Rate 3 mức (RQ2)**: Exact = **2,42%** (39.280 cụm) < Normalized (tree-sitter) = **7,83%** (37.103 cụm) < Near-duplicate (MinHash Jaccard $\ge 0,90$) = **9,09%** (36.595 cụm).
- **Label Quality (RQ3 & D5)**: **12,94%** hunk mang nhãn không cụ thể (`NVD-CWE-Other/noinfo`), **4,95%** đa nhãn, **168 cụm near-dup (1.037 hunk)** xung đột nhãn CWE giữa các CVE.
- **Xác thực trực tuyến 100 commit (D4)**: **94,0%** commit tồn tại trên repo gốc; **100,0%** (93/93) khớp tập file thay đổi (`results/validate_online.json`).
- **Tính tất định & Chống rò rỉ (D1 & D2)**: Chạy lại `build_dataset.py` cho SHA-256 trùng khớp 100% (`hunks.parquet`: `8db011193ba56076e6488003f1a84e43c2dfb4cbc3b171cadd177dad0e998e4a`); `split_project` đảm bảo **0 repo, 0 CVE, 0 cụm near-dup** chung giữa train và test ở cả 3 seed.

### 4.2. Bảng Kết quả Phân loại CWE qua 3 Seed `[42, 123, 2024]` (`results/evaluation/table_main_results.csv`)

| Exp | Cấu hình (`Split` / `Đặc trưng` / `Mô hình`) | Macro-F1 (Chính) | Weighted-F1 | MCC | Top-3 Acc | Accuracy | Train (s) |
|---|---|---:|---:|---:|---:|---:|---:|
| **E0** | `project` / `—` / `Dummy (stratified)` | 0,0572 ± 0,0024 | 0,0972 ± 0,0022 | -0,0002 ± 0,0021 | 0,1898 ± 0,0016 | 0,0988 ± 0,0020 | 0,02 |
| **E1** | `random_nodedup` / `before` / `TF-IDF + LR` | 0,6164 ± 0,0095 | 0,6543 ± 0,0080 | 0,6160 ± 0,0092 | 0,8364 ± 0,0034 | 0,6549 ± 0,0086 | 43,14 |
| **E2** | `random` (dedup) / `before` / `TF-IDF + LR` | 0,5792 ± 0,0018 | 0,6153 ± 0,0024 | 0,5732 ± 0,0029 | 0,8144 ± 0,0070 | 0,6170 ± 0,0035 | 45,37 |
| **E3** | **`project` (dedup) / `before` / `TF-IDF + LR` (Baseline)** | **0,2154 ± 0,0048** | **0,3199 ± 0,0056** | **0,2553 ± 0,0072** | **0,5884 ± 0,0024** | **0,3280 ± 0,0146** | **40,58** |
| **E4** | `project` (dedup) / `patch` (`before+after+DEL/ADD`) / `LR` | 0,2537 ± 0,0032 | 0,3637 ± 0,0043 | 0,3028 ± 0,0054 | 0,6167 ± 0,0057 | 0,3748 ± 0,0052 | 84,72 |
| **E5** | **`project` (dedup) / `patch_norm` (+ tree-sitter) / `LR` (Biến thể)** | **0,2545 ± 0,0014** | **0,3631 ± 0,0055** | **0,3002 ± 0,0081** | **0,6162 ± 0,0086** | **0,3698 ± 0,0081** | **130,64** |
| **E6** | `project` (dedup) / `patch_norm` / `LinearSVC` | 0,2584 ± 0,0035 | 0,3673 ± 0,0082 | 0,3058 ± 0,0113 | 0,5935 ± 0,0112 | 0,3760 ± 0,0110 | 204,49 |
| **E7** | `time` (test $\ge 2023$) / `patch_norm` / `TF-IDF + LR` | 0,2526 ± 0,0108 | 0,4085 ± 0,0139 | 0,3176 ± 0,0165 | 0,6488 ± 0,0070 | 0,4125 ± 0,0162 | 131,81 |

- **Kiểm định M2 (E5 vs E3)**: $\Delta\text{Macro-F1} = \mathbf{+0,0391}$ (+18,2% tương đối), CI 95% paired bootstrap dương và McNemar $p \le 10^{-5}$ ở **cả 3 seed**.
- **Kiểm định M5 / RQ4 (E2 vs E3)**: Chia ngẫu nhiên làm thổi phồng `Macro-F1` thêm $\mathbf{+0,3639}$ điểm (cao gấp **2,69 lần** chia theo dự án) do rò rỉ 918–948 repo và 1.703–1.742 CVE giữa train và test.

---

## 5. Cấu trúc Thư mục Gói Tái lập

```text
DT073/
├── configs/base.yaml            # Cấu hình tập trung (seed, ngưỡng lọc, top-17 CWE, split)
├── src/                         # Các module lõi của pipeline và mô hình
│   ├── cvefixes_db.py           # Kết nối SQLite + hàm giải nén zlib unz()
│   ├── metadata.py              # Truy vấn ứng viên file_change & quan hệ CVE-commit-CWE-fork
│   ├── validate.py              # Phễu lọc 9 lý do & xác thực commit online an toàn
│   ├── hunks.py                 # Parser diff chịu lỗi & ẩn danh email (<EMAIL>)
│   ├── normalize.py             # Chuẩn hóa AST đa ngôn ngữ bằng tree-sitter
│   ├── dedup.py                 # Khử trùng lặp 3 mức (exact, normalized, MinHash LSH near-dup)
│   ├── split.py                 # Chia tập random / project (đồ thị liên thông) / time
│   ├── features.py              # Trích đặc trưng 3 chế độ (before, patch, patch_norm)
│   ├── models.py                # Dummy, TF-IDF + LogisticRegression, LinearSVC / LightGBM
│   ├── evaluate.py              # Bootstrap CI 95%, Paired Bootstrap, McNemar, phân loại lỗi
│   └── utils.py                 # Quản lý seed, cấu hình, ghi run_meta.json
├── scripts/                     # Các script thực thi từng bước
├── tests/                       # 74 bài kiểm thử tự động (Unit / Integration / Negative)
├── data/                        # MANIFEST.json, processed/ (parquet + summary + SHA-256), reports/
├── results/                     # env.json, eda/, validate_online.json, label_audit/, experiments/, evaluation/
├── PREREGISTRATION.md           # Đăng ký trước giả thuyết, ma trận thí nghiệm & tiêu chí thành công
├── THREAT_MODEL.md              # Mô hình mối đe dọa, rò rỉ, quyền riêng tư & ranh giới tin cậy
├── mapping_paper.md             # Bảng ánh xạ định lượng kết quả với bài khảo sát Liang et al. (2025)
├── requirements-lock.txt        # Danh sách gói Python khóa phiên bản tuyệt đối (UTF-8)
└── run_all.ps1                  # Script chạy tự động toàn bộ pipeline từ đầu đến cuối
```

---

## 6. Trạng thái Hoàn thành

- [x] **Bước 1** – Phiếu tái lập bài báo khảo sát & bảng ánh xạ (`mapping_paper.md`)
- [x] **Bước 2** – Tải CVEfixes v1.0.8, kiểm tra MD5/SHA-256 (`data/MANIFEST.json`), dựng SQLite DB nén lossless & báo cáo dữ liệu (`data/reports/data_quality.md`)
- [x] **Bước 3** – Môi trường ảo tái lập (`.venv`), `requirements-lock.txt`, `results/env.json`
- [x] **Bước 4** – EDA 2 tầng (`results/eda/`), `THREAT_MODEL.md`, `PREREGISTRATION.md` (commit trước huấn luyện)
- [x] **Bước 5** – Pipeline trích xuất hunk, chuẩn hóa tree-sitter, dedup 3 mức, split chống rò rỉ, xác thực online 100 commit (D4), mẫu audit 200 hunk (D5), Baseline & Biến thể + **74 bài test (`pytest` 100% pass)**
- [x] **Bước 6** – Hoàn tất 24 lần chạy ma trận thí nghiệm `E0..E7 × 3 seed` (`results/experiments/`)
- [x] **Bước 7** – Đánh giá thống kê Bootstrap CI 95%, Paired Bootstrap, McNemar, ma trận nhầm lẫn, phân tích 50 mẫu lỗi (`results/evaluation/`) & cập nhật `mapping_paper.md`
- [x] **Bước 8** – Đóng gói tái lập (`run_all.ps1`, `scripts/demo_predict.py`, `README.md`, báo cáo đầy đủ)
