"""Unit + negative test cho src/hunks.py."""
from hunks import hunk_filter_reason, is_whitespace_only, parse_diff

DIFF_2 = (
    "@@ -10,4 +10,5 @@ static int parse(char *s)\n"
    " int n;\n"
    "-strcpy(buf, s);\n"
    "+if (strlen(s) >= sizeof(buf)) return -1;\n"
    "+strncpy(buf, s, sizeof(buf) - 1);\n"
    " return 0;\n"
    " }\n"
    "@@ -40,3 +41,3 @@ void f()\n"
    " a();\n"
    "-b(x);\n"
    "+b(y);\n"
    " c();\n"
)


def test_two_hunks_before_after():
    hs = parse_diff(DIFF_2)
    assert len(hs) == 2
    h = hs[0]
    assert (h.src_start, h.src_len, h.tgt_start, h.tgt_len) == (10, 4, 10, 5)
    assert h.section == "static int parse(char *s)"
    assert h.before == "int n;\nstrcpy(buf, s);\nreturn 0;\n}\n"
    assert "strncpy" in h.after and "strcpy(buf, s)" not in h.after
    assert h.removed == "strcpy(buf, s);\n" and h.n_added == 2 and h.n_context == 3
    assert h.warnings == []


def test_crlf_preserved_and_no_newline_marker():
    d = "@@ -1,2 +1,2 @@\r\n a\r\n-b\r\n+c\r\n\\ No newline at end of file\r\n"
    h = parse_diff(d)[0]
    assert h.before == "a\r\nb\r\n" and h.after == "a\r\nc\r\n"
    assert h.warnings == []


def test_header_without_counts():
    h = parse_diff("@@ -5 +5 @@\n-x\n+y\n")[0]
    assert (h.src_len, h.tgt_len) == (1, 1) and h.warnings == []


def test_git_headers_are_skipped():
    d = "diff --git a/f.c b/f.c\nindex 1..2 100644\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-x\n+y\n"
    assert len(parse_diff(d)) == 1


def test_empty_and_none():
    assert parse_diff(None) == [] and parse_diff("") == [] and parse_diff("   \n") == []


def test_garbage_does_not_raise():
    """Negative: diff hỏng không được làm crash pipeline."""
    assert parse_diff("not a diff at all\n\x00\x01") == []
    hs = parse_diff("@@ -1,5 +1,5 @@\n-x\n")      # số dòng không khớp header
    assert hs[0].warnings == ["count_mismatch"]
    hs = parse_diff("@@ -1,1 +1,1 @@\n?weird\n-x\n+y\n")
    assert "unexpected_line" in hs[0].warnings


def test_filters():
    ws = parse_diff("@@ -1 +1 @@\n-a = 1;\n+a  =  1;  \n")[0]
    assert is_whitespace_only(ws) and hunk_filter_reason(ws) == "whitespace_only"
    add_only = parse_diff("@@ -1,1 +1,2 @@\n x\n+if (!p) return;\n")[0]
    assert hunk_filter_reason(add_only) is None                       # mặc định giữ
    assert hunk_filter_reason(add_only, drop_add_only=True) == "add_only"
    long = parse_diff("@@ -1,300 +1,300 @@\n" + " c\n" * 299 + "-x\n+y\n")[0]
    assert hunk_filter_reason(long, max_lines=200) == "hunk_too_long"
