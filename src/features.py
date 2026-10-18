"""Bước 5f – Trích xuất chuỗi token đầu vào cho TF-IDF theo đúng 3 chế độ đã đăng ký trước:
  * "before"     (E1, E2, E3): chỉ token thô của mã trước bản vá (before)
  * "patch"      (E4)        : before + after + dòng xóa (DEL_) + dòng thêm (ADD_) + section (SEC_) + LANG_
  * "patch_norm" (E5, E6, E7): E4 + chuỗi token chuẩn hóa tree-sitter (NB_, NA_, NDEL_, NADD_, CDEL_, CADD_)
"""
from __future__ import annotations

import re
import pandas as pd

from normalize import tokenize

RAW_TOK = re.compile(
    r"[A-Za-z_]\w*|\d+(?:\.\d+)?|==|!=|<=|>=|->|::|&&|\|\||<<|>>|\S"
)
_ID_NUM = re.compile(r"^ID\d+$")
SEP = " <SEP> "


def raw_tokens(code: str | None) -> list[str]:
    """Tách token thô giữ nguyên tên hàm/biến, toán tử kép và chữ hoa/thường."""
    if not code:
        return []
    return RAW_TOK.findall(code)


def _canon(tok: str) -> str:
    """Gộp ID1, ID2... -> ID để bắt cấu trúc cú pháp bất biến theo vị trí biến."""
    return "ID" if _ID_NUM.match(tok) else tok


def _prefixed(prefix: str, toks: list[str]) -> str:
    if not toks:
        return ""
    return " ".join(f"{prefix}{t}" for t in toks)


def build_row_text(
    before: str | None,
    after: str | None = None,
    removed: str | None = None,
    added: str | None = None,
    section: str | None = None,
    lang: str | None = None,
    norm_before: str | None = None,
    norm_after: str | None = None,
    mode: str = "before",
) -> str:
    """Tạo chuỗi token cách nhau bởi khoảng trắng cho 1 hunk theo chế độ `mode`."""
    b_raw = " ".join(raw_tokens(before))
    if mode == "before":
        return b_raw

    if mode not in ("patch", "patch_norm"):
        raise ValueError(f"Unknown feature mode: {mode!r}")

    parts = [
        b_raw,
        _prefixed("AFT_", raw_tokens(after)),
        _prefixed("DEL_", raw_tokens(removed)),
        _prefixed("ADD_", raw_tokens(added)),
        _prefixed("SEC_", raw_tokens(section)),
        f"LANG_{(lang or 'UNK').replace(' ', '_')}",
    ]

    if mode == "patch_norm":
        nb = (norm_before.split() if isinstance(norm_before, str) and norm_before
              else tokenize(before or "", lang))
        na = (norm_after.split() if isinstance(norm_after, str) and norm_after
              else tokenize(after or "", lang))
        ndel = tokenize(removed or "", lang)
        nadd = tokenize(added or "", lang)
        parts.extend([
            _prefixed("NB_", nb),
            _prefixed("NA_", na),
            _prefixed("NDEL_", ndel),
            _prefixed("NADD_", nadd),
            _prefixed("CDEL_", [_canon(t) for t in ndel]),
            _prefixed("CADD_", [_canon(t) for t in nadd]),
        ])

    return SEP.join(p for p in parts if p)


def build_corpus(df: pd.DataFrame, mode: str = "before") -> list[str]:
    """Tạo danh sách văn bản đầu vào cho toàn bộ DataFrame hunk."""
    if mode == "before":
        return [" ".join(raw_tokens(b)) for b in df["before"].fillna("")]

    has_nb = "norm_before" in df.columns
    has_na = "norm_after" in df.columns
    has_sec = "section" in df.columns
    has_lang = "lang" in df.columns

    out: list[str] = []
    for r in df.itertuples(index=False):
        out.append(
            build_row_text(
                before=getattr(r, "before", ""),
                after=getattr(r, "after", ""),
                removed=getattr(r, "removed", ""),
                added=getattr(r, "added", ""),
                section=getattr(r, "section", "") if has_sec else "",
                lang=getattr(r, "lang", "") if has_lang else "",
                norm_before=getattr(r, "norm_before", None) if has_nb else None,
                norm_after=getattr(r, "norm_after", None) if has_na else None,
                mode=mode,
            )
        )
    return out
