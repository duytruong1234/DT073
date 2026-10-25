# ĐĂNG KÝ TRƯỚC: QUYẾT ĐỊNH & TIÊU CHÍ THÀNH CÔNG (Bước 4)

> Đề yêu cầu: *"xác định leakage, class imbalance, privacy, trust boundary và **tiêu chí thành công trước khi huấn luyện/triển khai**"*.
> Tài liệu này được **commit lên git trước khi chạy bất kỳ mô hình nào**. Mốc thời gian của commit là bằng chứng.
> Mọi thay đổi sau đó phải ghi ở mục 7 (Nhật ký sửa đổi) kèm lý do. Kết quả không đạt cũng phải báo cáo.

## 1. Câu hỏi nghiên cứu & giả thuyết

| RQ | Câu hỏi | Giả thuyết | Đo bằng |
|---|---|---|---|
| RQ1 | Bao nhiêu % bản ghi CVEfixes thành hunk hợp lệ? | H1: coverage giảm mạnh qua các bước lọc | Phễu coverage (D3) |
| RQ2 | Duplicate rate ở 3 mức? | H2: normalized > exact | `summary.json → duplicates` |
| RQ3 | Chất lượng nhãn CWE? | H3: tỷ lệ đáng kể nhãn không cụ thể/không khớp | Thống kê nhãn + audit thủ công (D5) |
| RQ4 | Rò rỉ ảnh hưởng thế nào? | H4: Macro-F1 random split > project split | E2 vs E3 (M5) |
| RQ5 | Biến thể có tốt hơn baseline? | H5: E5 > E3 có ý nghĩa thống kê | Quy tắc M2 |

## 2. Quyết định dữ liệu (chốt theo quy tắc viết sẵn trong `scripts/eda.py → RULES`)

| Quyết định | Quy tắc | Giá trị | Căn cứ |
|---|---|---|---|
| Ngôn ngữ | Ngôn ngữ lập trình, có tree-sitter, ≥ 1 500 file | PHP, C, JavaScript, Python, Java, TypeScript, C++, Go, Ruby | `results/eda/EDA_A.md` §A1 |
| Tangled commit | > p95 số file **mã nguồn**/commit | > 9 file → loại | §A2 (p50 = 1, p90 = 5, p95 = 9, p99 = 29) |
| File ADD/DELETE | Không có cặp trước/sau | loại | – |
| Merge commit | – | loại (thực tế không có file_change) | `data_quality.md` |
| Hunk | ≥ 1 dòng đổi, ≤ 200 dòng, không chỉ khoảng trắng; giữ hunk chỉ‑thêm | – | §B3 |
| Nhãn | Bỏ `NVD-CWE-Other/noinfo`; CVE nhiều CWE cụ thể → bỏ | – | §B4 |
| Top-K | CWE có ≥ 500 hunk đại diện | **K = 17** (phủ 58,8%) | §B1 |
| Lớp ngoài top-K | Loại (không gộp "Other") | – | lớp "Other" không đồng nhất |
| Dedup | Giữ 1 đại diện/cụm near-dup (Jaccard ≥ 0,9), đại diện = commit sớm nhất | – | §B4 |
| Split chính | **Project**: nhóm theo repo + fork + CVE + cụm near-dup; 70/10/20 | – | §B5 |
| Time split | train/val < 2023 ≤ test; nhóm theo CVE + near-dup | cutoff **2023** (test 16,1%) | §B2 |
| Privacy | Không xuất author/committer/msg; email → `<EMAIL>` | – | §A3, THREAT_MODEL §2 |
| Seed | 3 seed; mỗi seed đổi cả phép chia và mô hình | 42, 123, 2024 | đề yêu cầu ≥ 3 lần chạy |

## 3. Ma trận thí nghiệm (cố định trước)

Tập mô hình hóa: hunk đại diện near-dup có nhãn ∈ top-17 (trừ E1).

| Exp | Dữ liệu | Split | Đầu vào | Mô hình | Vai trò |
|---|---|---|---|---|---|
| E0 | như E3 | project | – | Dummy (majority, stratified) | Mức sàn |
| E1 | **không dedup** (mọi hunk top-K) | random | before (token thô) | TF-IDF + LR | Đo hiệu ứng trùng lặp + rò rỉ |
| E2 | dedup | random | before (token thô) | TF-IDF + LR | Đo rò rỉ (RQ4) |
| **E3** | dedup | **project** | before (token thô) | TF-IDF + LR | **BASELINE chính** |
| E4 | dedup | project | before + after (dòng xóa/thêm đánh dấu) | TF-IDF + LR | Ablation: thông tin bản vá |
| **E5** | dedup | project | E4 + chuẩn hóa tree-sitter | TF-IDF + LR | **BIẾN THỂ chính** |
| E6 | dedup | project | như E5 | LightGBM / LinearSVC | Biến thể mô hình |
| E7 | dedup | **time** | như E5 | TF-IDF + LR | Tổng quát hóa theo thời gian |

- TF-IDF: n-gram (1,2), `min_df=2`, `max_features=200 000`, `sublinear_tf=True`; `fit` chỉ trên train.
- LR: `class_weight="balanced"`, `C ∈ {0.1, 1, 10}` chọn trên **val** theo Macro-F1. LightGBM: tham số mặc định + early stopping trên val.
- **Tập test chỉ được đánh giá một lần cho mỗi (Exp, seed)**, sau khi đã chọn siêu tham số trên val.
- CodeBERT: không nằm trong ma trận chính (máy không có GPU) – nếu làm sẽ ghi là thí nghiệm thăm dò.

## 4. Tiêu chí thành công – DỮ LIỆU

| # | Tiêu chí | Ngưỡng / cách xác định |
|---|---|---|
| D1 | Tái lập dataset | 2 lần chạy `build_dataset.py` độc lập → **SHA-256 `hunks.parquet` trùng khớp** |
| D2 | Không rò rỉ ở project split | `leakage_report`: **0** repo, **0** CVE, **0** cụm near-dup chung giữa train và test, cả 3 seed |
| D3 | Coverage & duplicate rate | Báo cáo đầy đủ phễu (lý do loại từng bước) và duplicate rate 3 mức |
| D4 | Commit hợp lệ trên repo gốc | Kiểm tra online 100 commit ngẫu nhiên (seed 42): báo cáo tỷ lệ tồn tại & khớp file; nếu < 90% → ghi là mối đe dọa |
| D5 | Chất lượng nhãn | Audit 200 hunk (phân tầng theo CWE, seed 42), **2 người chấm độc lập**, báo cáo % hunk liên quan lỗ hổng, % CWE phù hợp và **Cohen's κ** |

## 5. Tiêu chí thành công – MÔ HÌNH

| # | Tiêu chí | Quy tắc |
|---|---|---|
| M0 | Metric | **Macro-F1 trên test của project split là metric chính.** Báo cáo thêm Weighted-F1, MCC, P/R/F1 từng lớp, Top-3 accuracy, confusion matrix. Accuracy chỉ là phụ |
| M1 | Baseline có ý nghĩa | E3 Macro-F1 > E0 (cả majority và stratified), CI 95% bootstrap không chồng lấn, ở cả 3 seed |
| M2 | Biến thể "tốt hơn" | E5 được coi là tốt hơn E3 **chỉ khi** ở **cả 3 seed**: ΔMacro-F1 > 0 **và** CI 95% paired bootstrap (1 000 lần) của Δ không chứa 0. Nếu không → kết luận "không có khác biệt có ý nghĩa" |
| M3 | Độ ổn định | Báo cáo mean ± std qua 3 seed; std Macro-F1 > 0,02 → đánh dấu "không ổn định" |
| M4 | Chi phí | Ghi thời gian train/infer, RAM đỉnh cho mọi (Exp, seed) |
| M5 | Hiệu ứng rò rỉ (RQ4) | H4 được ủng hộ nếu Macro-F1(E2) − Macro-F1(E3) > 0 và CI 95% bootstrap không chứa 0 ở cả 3 seed |
| M6 | Phân tích lỗi | 50 hunk test bị dự đoán sai của E5 (seed 42), phân loại nguyên nhân; confusion matrix cặp CWE cha–con |
| M7 | So với bài báo | Chỉ so sánh định tính theo `mapping_paper.md`; **không tuyên bố vượt bài báo** |

## 6. Quy tắc chống "chọn kết quả đẹp"

1. Không thêm/bớt thí nghiệm trong ma trận sau khi thấy kết quả test; thí nghiệm thêm phải ghi là "thăm dò".
2. Không đổi seed, top-K, ngưỡng lọc sau khi huấn luyện.
3. Mọi lần chạy (kể cả lỗi) lưu `results/<exp>/<seed>/` gồm config, log, dự đoán thô, metric, thời gian.

## 7. Nhật ký sửa đổi

| Ngày | Thay đổi | Lý do |
|---|---|---|
| 2026-10-19 | Bản đầu tiên (trước khi huấn luyện) | – |
| 2026-10-25 | **Sai lệch D5**: kế hoạch là 2 người chấm thủ công; thực tế thực hiện bằng **2 bộ luật chấm tự động độc lập** (`Coder_A`: cấu trúc/luồng điều khiển; `Coder_B`: từ vựng đặc thù CWE) trên 200 mẫu phân tầng (`scripts/label_audit.py heuristic`). Kết quả: κ<sub>liên quan</sub> = 0,6181; κ<sub>CWE</sub> = 0,5513 (`results/label_audit/audit_result.json`). Phiếu trống `audit_sheet_blank.csv` được giữ lại để chấm thủ công bổ sung. | Giới hạn nhân lực/thời gian; ghi nhận minh bạch thay vì sửa kế hoạch gốc |
