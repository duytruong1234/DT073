# DT073 – Trích cặp mã trước/sau sửa lỗi từ CVEfixes và phân loại CWE

Tái lập & mở rộng các nhận định của bài khảo sát *Survey of source code vulnerability analysis based on deep learning*
(Liang et al., Computers & Security 148, 2025, doi:10.1016/j.cose.2024.104098) trên bộ dữ liệu công khai **CVEfixes v1.0.8**.

> Dữ liệu: CVEfixes – Bhandari, Naseer, Moonen, PROMISE ’21, doi:10.1145/3475960.3475985 – giấy phép **CC BY 4.0**.

## 1. Yêu cầu hệ thống

| Thành phần | Đã kiểm thử |
|---|---|
| OS | Windows 10/11 (PowerShell) |
| Python | 3.12 |
| Git | ≥ 2.40 |
| Ổ đĩa trống | ≥ 40 GB (zip 12,7 GB + CSDL ~18 GB nén cột mã) |
| RAM | ≥ 8 GB |
| Mạng | tải 12,7 GB từ Zenodo |

Cấu hình máy thực tế của nhóm được ghi tự động trong `results/env.json`.

## 2. Cài đặt

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-lock.txt   # phiên bản đã khóa
.venv\Scripts\python -m pytest                                 # kiểm tra môi trường
.venv\Scripts\python scripts/env_info.py                       # ghi results/env.json
```

## 3. Chuẩn bị dữ liệu (Bước 2)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_step2.ps1
```

| Script | Đầu ra |
|---|---|
| `scripts/download_cvefixes.py` | `data/raw/CVEfixes_v1.0.8.zip` (resume, kiểm tra MD5) + `data/MANIFEST.json` |
| `scripts/build_sqlite.py` | `data/db/CVEfixes.db` (cột mã nén zlib, lossless; đọc bằng `src/cvefixes_db.py`) + `data/db_stats.json` |
| `scripts/data_report.py` | `data/reports/data_quality.json`, `docs/02_thong_ke_du_lieu.md` |

## 4. Cấu trúc thư mục

```
configs/      cấu hình (seed, ngưỡng lọc, chiến lược split) – base.yaml
data/         raw/ db/ interim/ processed/ reports/   (raw & db KHÔNG đưa lên git)
docs/         phiếu tái lập, các chương báo cáo nháp
scripts/      script chạy từng bước
src/          thư viện của đề tài (đọc DB, tiện ích tái lập, pipeline)
tests/        unit / integration / negative tests
notebooks/    EDA
results/      kết quả thô, log, cấu hình mỗi lần chạy
report/       báo cáo, slide
```

## 5. Tái lập

- Seed cố định: `configs/base.yaml → seeds: [42, 123, 2024]`.
- Mỗi lần chạy ghi `run_meta.json` (config, seed, git commit, môi trường) – xem `src/utils.py`.
- Checksum dữ liệu gốc và dữ liệu dẫn xuất: `data/MANIFEST.json`.

## 6. An toàn & đạo đức

Chỉ đọc dữ liệu công khai dạng văn bản; **không biên dịch/chạy** mã lỗ hổng trong dataset; không quét hay tấn công hệ thống thật.

## 7. Trạng thái

- [x] Bước 1 – Phiếu tái lập: `docs/01_phieu_tai_lap.md`
- [x] Bước 2 – Script tải/chuyển đổi dữ liệu (đang chạy nạp dữ liệu đầy đủ)
- [x] Bước 3 – Môi trường tái lập
- [ ] Bước 4 – EDA & threat model
- [ ] Bước 5 – Pipeline: validate commits → extract hunks → dedup → split; baseline & biến thể
- [ ] Bước 6 – Ma trận thí nghiệm
- [ ] Bước 7 – Đánh giá
- [ ] Bước 8 – Đóng gói
