"""Chuẩn hóa mã nguồn bằng tree-sitter (theo Fig.4 của bài báo: bỏ comment, đổi định danh -> ký hiệu).

Dùng cho:
  * dedup cấp "normalized" (hai hunk chỉ khác tên biến/comment/khoảng trắng -> coi là trùng)
  * biến thể mô hình (token đã chuẩn hóa thay cho token thô)

Hunk thường là đoạn mã bị cắt dở -> tree-sitter vẫn parse được (cây có node ERROR),
nên KHÔNG bao giờ ném ngoại lệ; ngôn ngữ không hỗ trợ -> fallback tokenizer regex.
"""
from __future__ import annotations

import re
from functools import lru_cache

# Tên ngôn ngữ trong CVEfixes (file_change.programming_language) -> tên grammar tree-sitter
LANG_MAP = {
    "C": "c", "C++": "cpp", "PHP": "php", "Python": "python", "Java": "java",
    "JavaScript": "javascript", "TypeScript": "typescript", "Go": "go", "Ruby": "ruby",
    "Rust": "rust", "C#": "csharp", "Scala": "scala", "Kotlin": "kotlin", "Swift": "swift",
    "Perl": "perl", "Lua": "lua", "Shell": "bash", "Objective-C": "objc",
}

COMMENT_TYPES = {"comment", "line_comment", "block_comment", "doc_comment", "documentation_comment"}
STRING_TYPES = {"string", "string_literal", "raw_string_literal", "char_literal", "character_literal",
                "interpreted_string_literal", "encapsed_string", "template_string", "heredoc",
                "string_value", "concatenated_string", "system_lib_string"}
NUMBER_TYPES = {"number_literal", "integer", "float", "integer_literal", "float_literal",
                "decimal_integer_literal", "decimal_floating_point_literal", "hex_integer_literal",
                "int_literal", "float_literal", "number"}
IDENT_TYPES = {"identifier", "field_identifier", "type_identifier", "property_identifier",
               "variable_name", "name", "shorthand_property_identifier", "constant",
               "namespace_identifier", "statement_identifier", "package_identifier"}

# Tên API/thư viện nhạy cảm bảo mật được GIỮ NGUYÊN khi chuẩn hóa (giống VulDeePecker: chỉ đổi
# tên do người dùng đặt, giữ lời gọi thư viện). Danh sách xấp xỉ – ghi rõ là giới hạn trong báo cáo.
KEEP_IDENTS = frozenset("""
strcpy strncpy strcat strncat sprintf snprintf vsprintf vsnprintf gets fgets scanf sscanf fscanf
memcpy memmove memset memcmp strlen strnlen strcmp strncmp strdup strndup strtok
malloc calloc realloc free alloca new delete sizeof
printf fprintf syslog fopen open read write recv send close fclose access stat chmod chown
system popen exec execl execlp execle execv execvp execve fork kill signal setuid setgid
rand srand random getenv putenv atoi atol strtol strtoul
copy_from_user copy_to_user get_user put_user kmalloc kzalloc kfree vmalloc vfree
assert abort exit
eval exec compile __import__ pickle loads yaml load subprocess shell os popen input open
mysql_query mysqli_query pg_query query execute prepare escape htmlspecialchars htmlentities
strip_tags addslashes urlencode base64_decode unserialize serialize include require
include_once require_once file_get_contents file_put_contents move_uploaded_file shell_exec passthru
innerHTML outerHTML document write writeln setTimeout setInterval Function JSON parse stringify
Runtime getRuntime ProcessBuilder Class forName newInstance ObjectInputStream readObject
Statement createStatement executeQuery executeUpdate PreparedStatement
send_file render redirect params request response cookies session
""".split())

_FALLBACK_TOKEN = re.compile(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|==|!=|<=|>=|->|::|&&|\|\||<<|>>|\S")
_FALLBACK_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*|#[^\n]*", re.S)
_KEYWORDS = frozenset("""
if else elif elsif unless for foreach while do switch case default break continue return goto try catch
finally throw throws raise except with as def fn func function fun sub class struct union enum interface
trait impl module package import from use using namespace public private protected static const final
var let val mut int long short char float double bool boolean void unsigned signed auto register
extern volatile inline typedef sizeof true false null nil None True False this self super and or not
in is new delete then end begin local my our echo print lambda yield async await go defer select chan
map type range
""".split())


@lru_cache(maxsize=None)
def _parser(ts_lang: str):
    try:
        from tree_sitter_language_pack import get_parser
        return get_parser(ts_lang)
    except Exception:
        return None


def _leaves(node):
    """Duyệt lá theo thứ tự; chuỗi/comment được trả về nguyên node (không đi sâu)."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in COMMENT_TYPES or n.type in STRING_TYPES or n.child_count == 0:
            yield n
        else:
            stack.extend(reversed(n.children))


def tokenize(code: str, lang: str | None, rename: bool = True, keep_comments: bool = False) -> list[str]:
    """Tách token có chuẩn hóa.

    rename=True: định danh -> ID1, ID2… theo thứ tự xuất hiện (cùng tên -> cùng ký hiệu);
                 chuỗi -> STR; số -> NUM.
    """
    if not code:
        return []
    ts = LANG_MAP.get(lang or "", (lang or "").lower())
    parser = _parser(ts) if ts else None
    if parser is None:
        return _fallback(code, rename)
    src = code
    prefix = 0
    if ts == "php" and "<?php" not in code[:200]:
        src = "<?php\n" + code   # grammar PHP cần thẻ mở
        prefix = len("<?php\n".encode())
    data = src.encode("utf-8", "surrogatepass")
    tree = parser.parse(data)
    names: dict[str, str] = {}
    out: list[str] = []
    for leaf in _leaves(tree.root_node):
        if leaf.end_byte <= prefix:
            continue
        text = data[leaf.start_byte:leaf.end_byte].decode("utf-8", "replace")
        t = leaf.type
        if t in COMMENT_TYPES:
            if keep_comments:
                out.append(text)
            continue
        if not text.strip():
            continue
        if rename:
            if t in STRING_TYPES:
                out.append("STR")
                continue
            if t in NUMBER_TYPES:
                out.append("NUM")
                continue
            if t in IDENT_TYPES:
                out.append(text if text in KEEP_IDENTS else names.setdefault(text, f"ID{len(names) + 1}"))
                continue
        out.append(text)
    return out


def _fallback(code: str, rename: bool) -> list[str]:
    code = _FALLBACK_COMMENT.sub(" ", code)
    toks = _FALLBACK_TOKEN.findall(code)
    if not rename:
        return toks
    names: dict[str, str] = {}
    out = []
    for t in toks:
        if t[0] in "\"'":
            out.append("STR")
        elif t[0].isdigit():
            out.append("NUM")
        elif t[0].isalpha() or t[0] == "_":
            out.append(t if (t in KEEP_IDENTS or t in _KEYWORDS or t.isupper())
                       else names.setdefault(t, f"ID{len(names) + 1}"))
        else:
            out.append(t)
    return out


def normalize(code: str, lang: str | None, rename: bool = True) -> str:
    """Chuỗi token chuẩn hóa nối bằng dấu cách."""
    return " ".join(tokenize(code, lang, rename=rename))
