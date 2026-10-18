# Bảng ánh xạ kết quả với bài báo

**Bài báo:** C. Liang, Q. Wei, J. Du, Y. Wang, Z. Jiang. *Survey of source code vulnerability analysis based on deep learning*. Computers & Security 148 (2025) 104098. doi:10.1016/j.cose.2024.104098

> [!IMPORTANT]
> Đây là bài **khảo sát**, không có dữ liệu/code/kết quả thực nghiệm riêng (mục *Data availability*: “No data was used”).
> Vì vậy bảng này đối chiếu **nhận định** của bài báo với **bằng chứng thực nghiệm** của đề tài trên CVEfixes v1.0.8,
> không so sánh “con số với con số” và **không tuyên bố vượt bài báo**.
> Cột *Kết quả* được điền sau Bước 6–7; mỗi ô trỏ tới file kết quả thô trong `results/`.

## 1. Nhận định của bài báo ↔ thí nghiệm của đề tài

| # | Nhận định / hạn chế trong bài báo | Vị trí | Thí nghiệm / phép đo trong DT073 | Kết quả | Kết luận (ủng hộ / không / chưa đủ bằng chứng) | File kết quả |
|---|---|---|---|---|---|---|
| L1 | CVE/NVD có chất lượng chú thích không nhất quán, nhãn sai, độ phủ không đầy đủ | 6.1.1, tr.14 | Tỷ lệ `NVD-CWE-Other/noinfo`; xung đột nhãn giữa hunk trùng; audit thủ công + Cohen’s κ; phễu coverage CVE→commit→file→hunk | _chờ_ | _chờ_ | `data/reports/`, `results/label_quality/` |
| L2 | Nhiễu & mất cân bằng dữ liệu làm giảm hiệu năng; vấn đề chưa được giải quyết | 6.1.1, tr.14 | Phân bố CWE long‑tail; so sánh có/không class_weight; Macro‑F1 vs Accuracy | _chờ_ | _chờ_ | `results/E3*/` |
| R | Russell et al.: khử dư thừa chỉ giữ lại 10,8% hàm | 3.2, tr.5 | Duplicate rate exact / normalized / near‑dup trên hunk CVEfixes | _chờ_ | _chờ_ | `results/dedup/` |
| L4 | Tổng quát hóa kém giữa ngôn ngữ / loại lỗ hổng | 6.1.3, tr.15 | Time split; kết quả theo từng ngôn ngữ | _chờ_ | _chờ_ | `results/E7*/` |
| L5 | Đánh đổi chi phí tiền xử lý ↔ hiệu năng | 6.1.4, tr.15 | Thời gian/RAM: TF‑IDF thô vs chuẩn hóa tree‑sitter vs (tùy chọn) CodeBERT | _chờ_ | _chờ_ | `results/*/cost.json` |
| T1 | Token thuần (BoW/N‑gram) không nắm được ngữ nghĩa sâu | 2.2.1, tr.3 | Baseline TF‑IDF+LR vs biến thể chuẩn hóa/biểu diễn giàu hơn | _chờ_ | _chờ_ | `results/E3*/`, `results/E5*/` |
| T2 | Chuẩn hóa (bỏ comment, đổi định danh → ký hiệu) là bước quan trọng | Fig.4, tr.5 | Ablation E4 → E5 (có/không chuẩn hóa tree‑sitter) | _chờ_ | _chờ_ | `results/E4*/`, `results/E5*/` |
| P | Mô hình pre‑trained (BERT/CodeBERT) là hướng triển vọng | 6.2.3, tr.15 | (Tùy chọn, cần GPU) fine‑tune CodeBERT | _chờ_ | _chờ_ | `results/E6*/` |

## 2. Khoảng trống bài báo chưa đề cập – đóng góp riêng của đề tài

| # | Khoảng trống | Căn cứ | Thí nghiệm | Kết quả | File |
|---|---|---|---|---|---|
| G1 | Rò rỉ train‑test (trùng repo/CVE/fork giữa train và test) | “leak” xuất hiện 0 lần trong bài | Random vs project vs time split (E1–E3, E7) | _chờ_ | `results/E1*–E3*/` |
| G2 | Phân loại đa lớp CWE trên cặp mã trước/sau sửa | Bài chủ yếu xét phân loại nhị phân | Top‑K CWE trên hunk before/after | _chờ_ | `results/` |
| G3 | CVEfixes không được khảo sát | “CVEfixes” xuất hiện 0 lần | Toàn bộ pipeline + thống kê dữ liệu | _chờ_ | `data/reports/` |

## 3. Metric sử dụng so với bài báo

| Bài báo nhắc tới | Đề tài báo cáo |
|---|---|
| Accuracy, Precision, Recall, F1, FPR/FNR, Top‑10 accuracy | Macro‑F1 (chính), Weighted‑F1, MCC, Precision/Recall từng lớp, Top‑3 accuracy, bootstrap CI 95%, McNemar test; coverage, label quality, duplicate rate |
