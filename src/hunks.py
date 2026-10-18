"""Tách unified diff (cột file_change.diff của CVEfixes) thành các hunk before/after.

Diff của CVEfixes (sinh bởi PyDriller) KHÔNG có dòng '--- a/' '+++ b/', bắt đầu thẳng bằng '@@'.
Parser tự viết (không phụ thuộc unidiff) để chịu được diff lỗi: không bao giờ ném ngoại lệ,
mà ghi cảnh báo vào trường `warnings`.

Mỗi hunk:
    before  = dòng ngữ cảnh + dòng bị xóa   (mã TRƯỚC khi sửa – "vulnerable")
    after   = dòng ngữ cảnh + dòng được thêm (mã SAU khi sửa – "fixed")
    removed / added = chỉ các dòng thay đổi
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")


@dataclass
class Hunk:
    idx: int
    src_start: int
    src_len: int
    tgt_start: int
    tgt_len: int
    section: str                      # phần sau @@ ... @@ (git thường ghi tên hàm bao quanh)
    before: str = ""
    after: str = ""
    removed: str = ""
    added: str = ""
    n_removed: int = 0
    n_added: int = 0
    n_context: int = 0
    warnings: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["warnings"] = ";".join(self.warnings)
        return d


def _finish(h: Hunk, b: list, a: list, rem: list, add: list) -> Hunk:
    h.before, h.after = "".join(b), "".join(a)
    h.removed, h.added = "".join(rem), "".join(add)
    h.n_removed, h.n_added = len(rem), len(add)
    if h.n_context + h.n_removed != h.src_len or h.n_context + h.n_added != h.tgt_len:
        h.warnings.append("count_mismatch")
    return h


def parse_diff(diff: str | None) -> list[Hunk]:
    """Tách diff thành danh sách Hunk. Diff rỗng/None -> []."""
    if not diff or not diff.strip():
        return []
    hunks: list[Hunk] = []
    cur, b, a, rem, add = None, [], [], [], []
    preamble_warned = False
    for line in diff.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        m = HUNK_RE.match(bare)
        if m:
            if cur is not None:
                hunks.append(_finish(cur, b, a, rem, add))
            s1, l1, s2, l2, sec = m.groups()
            cur = Hunk(len(hunks), int(s1), int(l1) if l1 is not None else 1,
                       int(s2), int(l2) if l2 is not None else 1, sec.strip())
            b, a, rem, add = [], [], [], []
            continue
        if cur is None:
            # Dòng trước hunk đầu tiên (header diff --git, ---/+++ hoặc rác) – bỏ qua
            if bare.startswith(("diff ", "--- ", "+++ ", "index ", "new file", "deleted file",
                                "similarity", "rename ", "old mode", "new mode", "Binary files")):
                continue
            if bare.strip() and not preamble_warned:
                preamble_warned = True
            continue
        tag, body = (line[:1], line[1:]) if line else ("", "")
        if tag == " " or (tag == "" and bare == ""):
            b.append(body)
            a.append(body)
            cur.n_context += 1
        elif tag == "-":
            b.append(body)
            rem.append(body)
        elif tag == "+":
            a.append(body)
            add.append(body)
        elif tag == "\\":
            pass  # "\ No newline at end of file"
        else:
            cur.warnings.append("unexpected_line")
    if cur is not None:
        hunks.append(_finish(cur, b, a, rem, add))
    return hunks


def is_whitespace_only(h: Hunk) -> bool:
    """Hunk chỉ thay đổi khoảng trắng/xuống dòng (không thay đổi nội dung thực)."""
    return re.sub(r"\s+", "", h.removed) == re.sub(r"\s+", "", h.added)


EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")


def mask_emails(text: str) -> tuple[str, int]:
    """Privacy: thay email bằng <EMAIL>. Trả về (văn bản mới, số email đã che)."""
    if not text:
        return text, 0
    return EMAIL_RE.subn("<EMAIL>", text)


def hunk_filter_reason(h: Hunk, min_changed: int = 1, max_lines: int = 200,
                       drop_whitespace_only: bool = True, drop_add_only: bool = False) -> str | None:
    """Trả về lý do loại hunk (None nếu giữ). Ngưỡng lấy từ configs/base.yaml -> hunks.

    Mặc định GIỮ hunk chỉ thêm dòng: bản vá bảo mật thường chỉ chèn thêm kiểm tra
    (VD `if (len > max) return -1;`), khi đó `before` là vùng mã lỗi (ngữ cảnh).
    """
    if h.n_removed + h.n_added < min_changed:
        return "no_change"
    if drop_whitespace_only and is_whitespace_only(h):
        return "whitespace_only"
    if max(h.n_context + h.n_removed, h.n_context + h.n_added) > max_lines:
        return "hunk_too_long"
    if drop_add_only and h.n_removed == 0:
        return "add_only"
    return None
