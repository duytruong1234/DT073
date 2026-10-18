# Thống kê dữ liệu CVEfixes (tự sinh bởi `scripts/data_report.py`)

## Nguồn & phiên bản

| Mục | Giá trị |
|---|---|
| Dataset | CVEfixes v1.0.8 (CVE công bố đến 23/07/2024) |
| DOI | 10.5281/zenodo.4476563 |
| Giấy phép | CC BY 4.0 (dữ liệu), MIT (mã nguồn thu thập) |
| Ngày tải | 2026-10-19T03:07:15 |
| File gốc | `CVEfixes_v1.0.8.zip` – MD5 `4586a358977acfa4c60b1a2cdd096221` – SHA‑256 `6acd55aaeb7ffcfc20fdcebf7df88d206f9892ef64b0f2a2e06864d5b44b3a83` |
| CSDL dẫn xuất | `CVEfixes.db` – SHA‑256 `c51f67d8433efbfb3ad40b542d8ffb98a9c3d4fe72d7c916cff3b0f79751245d` – cột nén: {'file_change': ['code_after', 'code_before', 'diff_parsed'], 'method_change': ['code']} |

## Số dòng theo bảng

| Bảng | Số dòng |
|---|---:|
| fixes | 12,923 |
| commits | 12,107 |
| file_change | 51,342 |
| method_change | 277,948 |
| cve | 11,873 |
| cwe | 272 |
| cwe_classification | 12,198 |
| repository | 4,249 |

CVE trong `fixes`: **11,873** · commit: **12,103** · repo: **4,249**

## Nhãn CWE

- Số CWE khác nhau: **272**; CVE có nhãn CWE: **11,873**
- `NVD-CWE-Other`: 301 CVE · `NVD-CWE-noinfo`: 1,162 CVE
- CVE **chỉ** có nhãn không cụ thể: **1,458** (12.3%)
- CVE trong `fixes` không có CWE: 0
- Số CWE / CVE: {1: 11568, 2: 287, 3: 16, 4: 2}

| # | CWE | Số CVE | Tỷ lệ |
|---:|---|---:|---:|
| 1 | CWE-79 | 1,794 | 15.1% |
| 2 | NVD-CWE-noinfo | 1,162 | 9.8% |
| 3 | CWE-125 | 553 | 4.7% |
| 4 | CWE-787 | 450 | 3.8% |
| 5 | CWE-20 | 408 | 3.4% |
| 6 | CWE-89 | 403 | 3.4% |
| 7 | CWE-119 | 384 | 3.2% |
| 8 | CWE-22 | 383 | 3.2% |
| 9 | CWE-476 | 379 | 3.2% |
| 10 | NVD-CWE-Other | 301 | 2.5% |
| 11 | CWE-200 | 295 | 2.5% |
| 12 | CWE-416 | 275 | 2.3% |
| 13 | CWE-352 | 246 | 2.1% |
| 14 | CWE-190 | 225 | 1.9% |
| 15 | CWE-287 | 146 | 1.2% |
| 16 | CWE-94 | 146 | 1.2% |
| 17 | CWE-78 | 143 | 1.2% |
| 18 | CWE-918 | 143 | 1.2% |
| 19 | CWE-264 | 141 | 1.2% |
| 20 | CWE-863 | 126 | 1.1% |
| 21 | CWE-362 | 125 | 1.1% |
| 22 | CWE-400 | 123 | 1.0% |
| 23 | CWE-74 | 112 | 0.9% |
| 24 | CWE-601 | 107 | 0.9% |
| 25 | CWE-120 | 102 | 0.9% |

## Commit

- Dòng `fixes` không khớp commit: 0
- Commit không có file_change: 918
- Cùng hash xuất hiện ở nhiều repo (fork): 4
- Merge commit: 908
- Số file / commit: {'p50': 2, 'p90': 6, 'p99': 38, 'max': 2142} · commit > 10 file (nghi tangled): 595

| Repo | Số commit |
|---|---:|
| https://github.com/torvalds/linux | 1,172 |
| https://github.com/tensorflow/tensorflow | 431 |
| https://github.com/vim/vim | 181 |
| https://github.com/ImageMagick/ImageMagick | 180 |
| https://github.com/xwiki/xwiki-platform | 151 |
| https://github.com/gpac/gpac | 135 |
| https://github.com/phpmyadmin/phpmyadmin | 126 |
| https://github.com/the-tcpdump-group/tcpdump | 104 |
| https://github.com/FFmpeg/FFmpeg | 103 |
| https://github.com/MISP/MISP | 96 |
| https://github.com/pimcore/pimcore | 84 |
| https://github.com/microweber/microweber | 81 |
| https://github.com/discourse/discourse | 72 |
| https://github.com/thorsten/phpmyfaq | 68 |
| https://github.com/radareorg/radare2 | 64 |

## File thay đổi

- Thiếu `code_before` (file mới): 9,272 (18.1%)
- Thiếu `code_after` (file bị xóa): 4,126 (8.0%)
- Diff rỗng: 0
- Số dòng thay đổi / file: {'p50': 9, 'p90': 99, 'p99': 698, 'max': 208630}
- **Trùng lặp diff (exact, sơ bộ)**: 3,254 / 51,342 = **0.0634**

| Ngôn ngữ | Số file | Tỷ lệ |
|---|---:|---:|
| PHP | 12,464 | 24.3% |
| C | 6,220 | 12.1% |
| unknown | 4,126 | 8.0% |
| JavaScript | 3,656 | 7.1% |
| Markdown | 2,942 | 5.7% |
| Python | 2,753 | 5.4% |
| Java | 2,571 | 5.0% |
| TypeScript | 2,563 | 5.0% |
| C++ | 2,252 | 4.4% |
| Go | 1,919 | 3.7% |
| Ruby | 1,917 | 3.7% |
| HTML | 1,499 | 2.9% |
| Shell | 1,081 | 2.1% |
| CoffeeScript | 735 | 1.4% |
| SQL | 685 | 1.3% |
| C# | 484 | 0.9% |
| Batchfile | 457 | 0.9% |
| Scala | 395 | 0.8% |
| Lua | 393 | 0.8% |
| Perl | 341 | 0.7% |

| change_type | Số file |
|---|---:|
| ModificationType.MODIFY | 37,639 |
| ModificationType.ADD | 9,269 |
| ModificationType.DELETE | 4,124 |
| ModificationType.RENAME | 310 |

## Commit theo năm

| Năm | Số commit |
|---|---:|
| 1999 | 2 |
| 2001 | 1 |
| 2005 | 1 |
| 2006 | 3 |
| 2007 | 8 |
| 2008 | 17 |
| 2009 | 15 |
| 2010 | 48 |
| 2011 | 123 |
| 2012 | 231 |
| 2013 | 328 |
| 2014 | 449 |
| 2015 | 499 |
| 2016 | 693 |
| 2017 | 899 |
| 2018 | 632 |
| 2019 | 709 |
| 2020 | 994 |
| 2021 | 1,658 |
| 2022 | 2,075 |
| 2023 | 1,837 |
| 2024 | 885 |
