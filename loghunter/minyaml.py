"""
Sigma benzeri kural dosyalari icin minimal YAML alt kumesi parser'i.

PyYAML kurulu ise otomatik olarak o kullanilir. Degilse bu modul devreye girer.
Desteklenen: ic ice haritalar, skaler listeler, harita listeleri, yorumlar,
tirnakli/tirnaksiz skalerler, bool/int/float/null donusumu, '|' blok metin.
"""
from __future__ import annotations

try:  # pragma: no cover - ortama bagli
    import yaml as _pyyaml
except Exception:  # pragma: no cover
    _pyyaml = None


def _scalar(tok: str):
    tok = tok.strip()
    if tok == "" or tok in ("~", "null", "Null", "NULL"):
        return None
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[1:-1]
    low = tok.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    if tok.startswith("[") and tok.endswith("]"):
        inner = tok[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in inner.split(",")]
    return tok


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (not out or out[-1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _tokenize(text: str):
    """(indent, content) ciftleri uretir; bos satir ve yorumlar atilir."""
    rows = []
    for raw in text.replace("\t", "    ").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        content = _strip_comment(raw)
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        rows.append((indent, content.strip()))
    return rows


def _parse_block(rows, idx: int, indent: int):
    """rows[idx:] icindeki `indent` seviyesindeki blogu parse eder."""
    if idx >= len(rows):
        return None, idx

    if rows[idx][1].startswith("- "):
        items = []
        while idx < len(rows) and rows[idx][0] == indent and rows[idx][1].startswith("- "):
            item = rows[idx][1][2:].strip()
            child_indent = indent + 2
            if item == "":
                val, idx = _parse_block(rows, idx + 1, child_indent)
                items.append(val)
            elif ":" in item and not item.split(":", 1)[1].strip().startswith("//"):
                # liste elemani bir harita
                virtual = [(child_indent, item)]
                j = idx + 1
                while j < len(rows) and rows[j][0] >= child_indent:
                    virtual.append(rows[j])
                    j += 1
                val, _ = _parse_block(virtual, 0, child_indent)
                items.append(val)
                idx = j - 1
            else:
                items.append(_scalar(item))
            idx += 1
        return items, idx

    mapping = {}
    while idx < len(rows) and rows[idx][0] == indent:
        line = rows[idx][1]
        if line.startswith("- "):
            break
        if ":" not in line:
            idx += 1
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-"):
            buf, j = [], idx + 1
            while j < len(rows) and rows[j][0] > indent:
                buf.append(rows[j][1])
                j += 1
            mapping[key] = ("\n" if rest.startswith("|") else " ").join(buf)
            idx = j
            continue
        if rest == "":
            nxt = idx + 1
            if nxt < len(rows) and rows[nxt][0] > indent:
                val, idx = _parse_block(rows, nxt, rows[nxt][0])
                mapping[key] = val
                continue
            mapping[key] = None
            idx += 1
            continue
        mapping[key] = _scalar(rest)
        idx += 1
    return mapping, idx


def loads(text: str):
    """YAML metnini Python nesnesine cevirir."""
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    rows = _tokenize(text)
    if not rows:
        return None
    data, _ = _parse_block(rows, 0, rows[0][0])
    return data


def load_file(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
