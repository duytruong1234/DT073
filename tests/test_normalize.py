"""Unit + negative test cho src/normalize.py."""
from normalize import normalize, tokenize


def test_rename_makes_equivalent_code_equal():
    a = "int total = count + 1; // tăng\nreturn total;"
    b = "int  s=n+1;   /* comment khác */\nreturn s;"
    assert normalize(a, "C") == normalize(b, "C")


def test_different_logic_stays_different():
    assert normalize("x = a + b;", "C") != normalize("x = a - b;", "C")


def test_literals_and_comments():
    toks = tokenize('printf("hello %d", 42); // c', "C")
    assert "STR" in toks and "NUM" in toks and "//" not in " ".join(toks)
    assert "printf" in toks                     # API nhạy cảm được giữ nguyên


def test_sensitive_api_kept_user_names_renamed():
    toks = tokenize("strcpy(dst, src);", "C")
    assert toks[0] == "strcpy" and "dst" not in toks and "ID1" in toks


def test_keywords_kept():
    toks = tokenize("if (p == NULL) { return -1; }", "C")
    assert "if" in toks and "return" in toks


def test_php_fragment_without_open_tag():
    toks = tokenize('$q = "SELECT * FROM t WHERE id=" . $id; mysql_query($q);', "PHP")
    assert "mysql_query" in toks and "STR" in toks and "<?php" not in toks


def test_python_and_java():
    assert normalize("def f(x):\n    return eval(x)\n", "Python").count("eval") == 1
    assert "ID1" in normalize("class A { int f(String s) { return s.length(); } }", "Java")


def test_broken_fragment_does_not_raise():
    """Negative: hunk cắt dở giữa hàm vẫn tách token được."""
    toks = tokenize("  if (len > max) {\n    memcpy(buf, src, len);", "C")
    assert "memcpy" in toks and len(toks) > 5


def test_unknown_language_uses_fallback():
    toks = tokenize('foo bar = "x"; # comment\nif bar then baz end', "Brainfuck++")
    assert "STR" in toks and "if" in toks and "comment" not in toks


def test_empty():
    assert tokenize("", "C") == [] and normalize(None, "C") == ""
