"""Sigma benzeri kural modeli ve eslestirme mantigi."""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .minyaml import load_file

LEVEL_SCORE = {
    "informational": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


class RuleError(ValueError):
    """Hatali kural dosyasi."""


# --------------------------------------------------------------------------- #
# Alan karsilastirma
# --------------------------------------------------------------------------- #
def _as_list(value: Any) -> List[Any]:
    if value is None:
        return [None]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _norm(value: Any) -> str:
    return "" if value is None else str(value)


def _cmp_number(event_value: Any, expected: Any, op: str) -> bool:
    try:
        a, b = float(event_value), float(expected)
    except (TypeError, ValueError):
        return False
    return {
        "gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b,
    }[op]


def _match_single(event_value: Any, expected: Any, modifiers: List[str]) -> bool:
    ev = _norm(event_value)
    ev_low = ev.lower()

    for op in ("gt", "gte", "lt", "lte"):
        if op in modifiers:
            return _cmp_number(event_value, expected, op)

    if "re" in modifiers:
        try:
            return re.search(str(expected), ev, re.IGNORECASE) is not None
        except re.error as exc:
            raise RuleError(f"gecersiz regex: {expected} ({exc})") from exc

    exp = _norm(expected).lower()
    if "contains" in modifiers:
        return exp in ev_low
    if "startswith" in modifiers:
        return ev_low.startswith(exp)
    if "endswith" in modifiers:
        return ev_low.endswith(exp)
    if "cidr" in modifiers:
        return _match_cidr(ev, _norm(expected))

    if any(c in exp for c in "*?"):
        return fnmatch.fnmatch(ev_low, exp)
    return ev_low == exp


def _match_cidr(ip: str, cidr: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _get_field(event: Dict[str, Any], name: str) -> Any:
    """Nokta ile ic ice alan destegi + buyuk/kucuk harf duyarsiz arama."""
    if name in event:
        return event[name]
    if "." in name:
        cur: Any = event
        for part in name.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur is not None:
            return cur
    lowered = name.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def _match_field(event: Dict[str, Any], spec_key: str, spec_val: Any) -> bool:
    parts = spec_key.split("|")
    field_name, modifiers = parts[0], [p.lower() for p in parts[1:]]
    event_value = _get_field(event, field_name)

    expected_values = _as_list(spec_val)
    if "all" in modifiers:
        return all(
            any(_match_single(v, exp, modifiers) for v in _as_list(event_value))
            for exp in expected_values
        )
    return any(
        any(_match_single(v, exp, modifiers) for v in _as_list(event_value))
        for exp in expected_values
    )


def _match_block(event: Dict[str, Any], block: Any) -> bool:
    """Bir selection/filter blogunu degerlendirir."""
    if isinstance(block, list):
        # liste = OR (her eleman bir harita ya da 'keywords' skaleri)
        for item in block:
            if isinstance(item, dict):
                if all(_match_field(event, k, v) for k, v in item.items()):
                    return True
            else:
                blob = " ".join(_norm(v) for v in event.values()).lower()
                if _norm(item).lower() in blob:
                    return True
        return False
    if isinstance(block, dict):
        return all(_match_field(event, k, v) for k, v in block.items())
    blob = " ".join(_norm(v) for v in event.values()).lower()
    return _norm(block).lower() in blob


# --------------------------------------------------------------------------- #
# condition ifadesi degerlendirme
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"\(|\)|\ball of\b|\b1 of\b|\bany of\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_*]*")


class _ConditionParser:
    """Sigma condition alt kumesi: and / or / not / () / '1 of x*' / 'all of x*'."""

    def __init__(self, expr: str, results: Dict[str, bool]):
        self.tokens = [t.strip() for t in _TOKEN_RE.findall(expr or "")]
        self.pos = 0
        self.results = results

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> Optional[str]:
        tok = self._peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse(self) -> bool:
        if not self.tokens:
            return any(self.results.values())
        value = self._or()
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._next()
            value = self._and() or value
        return value

    def _and(self) -> bool:
        value = self._unary()
        while self._peek() == "and":
            self._next()
            value = self._unary() and value
        return value

    def _unary(self) -> bool:
        tok = self._peek()
        if tok == "not":
            self._next()
            return not self._unary()
        return self._primary()

    def _primary(self) -> bool:
        tok = self._next()
        if tok == "(":
            value = self._or()
            if self._peek() == ")":
                self._next()
            return value
        if tok in ("all of", "1 of", "any of"):
            target = self._next() or ""
            if target == "them":
                target = "*"
            matched = [v for k, v in self.results.items() if fnmatch.fnmatch(k, target)]
            if not matched:
                return False
            return all(matched) if tok == "all of" else any(matched)
        if tok in (None, ")"):
            return False
        return bool(self.results.get(tok, False))


# --------------------------------------------------------------------------- #
# Kural
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    title: str
    description: str = ""
    level: str = "medium"
    author: str = ""
    logsource: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source_path: str = ""

    @property
    def score(self) -> int:
        return LEVEL_SCORE.get(str(self.level).lower(), 50)

    @property
    def mitre(self) -> List[str]:
        return [t for t in self.tags if str(t).lower().startswith("attack.")]

    # ------------------------------------------------------------------ #
    def logsource_matches(self, event: Dict[str, Any]) -> bool:
        """Kuralin logsource'u olay kaynagiyla uyusuyor mu."""
        if not self.logsource:
            return True
        for key in ("product", "service", "category"):
            expected = self.logsource.get(key)
            if not expected:
                continue
            actual = _norm(event.get(f"_{key}") or event.get(key))
            if actual and actual.lower() != str(expected).lower():
                return False
        return True

    def matches(self, event: Dict[str, Any]) -> bool:
        if not self.logsource_matches(event):
            return False
        blocks = {k: v for k, v in self.detection.items() if k != "condition"}
        if not blocks:
            return False
        results = {name: _match_block(event, block) for name, block in blocks.items()}
        condition = self.detection.get("condition") or " and ".join(blocks)
        return _ConditionParser(str(condition), results).parse()


def rule_from_dict(data: Dict[str, Any], source_path: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{source_path}: kural bir harita olmali")
    if "detection" not in data or not isinstance(data["detection"], dict):
        raise RuleError(f"{source_path}: 'detection' bolumu eksik")
    if "title" not in data:
        raise RuleError(f"{source_path}: 'title' alani eksik")
    return Rule(
        id=str(data.get("id") or os.path.basename(source_path) or data["title"]),
        title=str(data["title"]),
        description=str(data.get("description") or ""),
        level=str(data.get("level") or "medium"),
        author=str(data.get("author") or ""),
        logsource=data.get("logsource") or {},
        detection=data["detection"],
        tags=[str(t) for t in (data.get("tags") or [])],
        falsepositives=[str(t) for t in (data.get("falsepositives") or [])],
        references=[str(t) for t in (data.get("references") or [])],
        source_path=source_path,
    )


def load_rules(path: str) -> List[Rule]:
    """Tek dosya ya da dizin (recursive) icinden kurallari yukler."""
    files: List[str] = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.lower().endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, name))
    else:
        files.append(path)

    rules: List[Rule] = []
    for file_path in files:
        data = load_file(file_path)
        rules.append(rule_from_dict(data, file_path))
    return rules


def filter_rules(rules: Iterable[Rule], min_level: str = "informational",
                 tag: Optional[str] = None) -> List[Rule]:
    floor = LEVEL_SCORE.get(min_level.lower(), 0)
    out = [r for r in rules if r.score >= floor]
    if tag:
        out = [r for r in out if any(tag.lower() in t.lower() for t in r.tags)]
    return out
