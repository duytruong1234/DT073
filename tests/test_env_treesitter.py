"""Kiểm tra môi trường: tree-sitter parse được các ngôn ngữ dự kiến dùng (Bước 3)."""
import pytest

tslp = pytest.importorskip("tree_sitter_language_pack")

SAMPLES = {
    "c": "int f(char *s) { char buf[8]; strcpy(buf, s); return 0; }",
    "cpp": "class A { public: int g(std::string s) { return s.size(); } };",
    "php": "<?php function q($id) { return mysql_query(\"SELECT * FROM t WHERE id=$id\"); } ?>",
    "python": "def f(x):\n    return eval(x)\n",
    "java": "class A { int f(String s) { return s.length(); } }",
    "javascript": "function f(x) { document.write(x); }",
    "go": "package main\nfunc f(x int) int { return x + 1 }\n",
    "ruby": "def f(x)\n  system(x)\nend\n",
}

FUNC_NODE = {"c": "function_definition", "cpp": "function_definition", "php": "function_definition",
             "python": "function_definition", "java": "method_declaration", "javascript": "function_declaration",
             "go": "function_declaration", "ruby": "method"}


def _walk(node):
    yield node
    for ch in node.children:
        yield from _walk(ch)


@pytest.mark.parametrize("lang", sorted(SAMPLES))
def test_parse_without_errors(lang):
    parser = tslp.get_parser(lang)
    tree = parser.parse(SAMPLES[lang].encode("utf-8"))
    assert not tree.root_node.has_error, f"{lang}: cây cú pháp có lỗi"
    types = {n.type for n in _walk(tree.root_node)}
    assert FUNC_NODE[lang] in types, f"{lang}: không tìm thấy node hàm"


def test_broken_code_is_tolerated():
    """Negative: mã hỏng (thường gặp trong hunk bị cắt) không làm crash, chỉ đánh dấu lỗi."""
    tree = tslp.get_parser("c").parse(b"int f( { if (x) { return ;")
    assert tree.root_node.has_error
