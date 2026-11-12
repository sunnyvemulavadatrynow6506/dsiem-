"""Parser for Kibana Query Language (KQL) as used by the supplied 'query', 'new_terms' and 'threshold' rules.

Semantics (Elasticsearch): ``field : value`` on a keyword field is an exact,
case-sensitive match; an unquoted value containing ``*`` is a wildcard; a
quoted value is literal.  On a *text* field (``powershell.file.script_block_text``,
``message``) a quoted value is a phrase query over analysed (lower-cased) word
tokens and an unquoted value matches single tokens.
"""
from __future__ import annotations

import re
from typing import Any

from eql import Unsupported

ESCAPED_STAR = "\x00"
TEXT_FIELDS = {"powershell.file.script_block_text", "message", "winlog.event_data.ScriptBlockText"}

TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<op>\(|\)|\{|\}|:|<=|>=|<|>)
  | (?P<word>(?:\\.|[^\s()":{}<>\\])+)
""", re.X | re.S)


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = TOKEN.match(text, pos)
        if not match:
            raise Unsupported(f"KQL syntax not understood near {text[pos:pos + 30]!r}")
        pos = match.end()
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "ws":
            continue
        if kind == "word" and value.lower() in ("and", "or", "not"):
            out.append(("kw", value.lower()))
        else:
            out.append((kind, value))
    out.append(("eof", ""))
    return out


def _unescape_word(word: str) -> tuple[str, bool]:
    """Unquoted KQL value -> (pattern text with '*' wildcards, has_wildcard)."""
    out = []
    wild = False
    i = 0
    while i < len(word):
        ch = word[i]
        if ch == "\\" and i + 1 < len(word):
            nxt = word[i + 1]
            out.append(ESCAPED_STAR if nxt == "*" else nxt)
            i += 2
            continue
        if ch == "*":
            wild = True
        out.append(ch)
        i += 1
    return "".join(out), wild


def _unescape_string(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text[1:-1])


class Parser:
    def __init__(self, text: str):
        self.toks = _tokens(text)
        self.i = 0

    def peek(self, k: int = 0) -> tuple[str, str]:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def take(self) -> tuple[str, str]:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def accept(self, kind: str, value: str | None = None) -> bool:
        tok = self.peek()
        if tok[0] == kind and (value is None or tok[1] == value):
            self.i += 1
            return True
        return False

    def expect(self, kind: str, value: str | None = None) -> None:
        if not self.accept(kind, value):
            raise Unsupported(f"KQL: expected {value or kind}, found {self.peek()[1]!r}")

    def parse(self) -> dict[str, Any]:
        node = self.or_expr()
        self.expect("eof")
        return node

    def or_expr(self) -> dict[str, Any]:
        parts = [self.and_expr()]
        while self.accept("kw", "or"):
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else {"any": parts}

    def and_expr(self) -> dict[str, Any]:
        parts = [self.not_expr()]
        while True:
            if self.accept("kw", "and"):
                parts.append(self.not_expr())
            else:
                break
        return parts[0] if len(parts) == 1 else {"all": parts}

    def not_expr(self) -> dict[str, Any]:
        if self.accept("kw", "not"):
            return {"not": self.not_expr()}
        return self.primary()

    def primary(self) -> dict[str, Any]:
        if self.accept("op", "("):
            node = self.or_expr()
            self.expect("op", ")")
            return node
        kind, text = self.take()
        if kind != "word":
            raise Unsupported(f"KQL free-text search or unexpected token {text!r} (only field queries are translated)")
        field = text.replace("\\", "")
        if self.accept("op", "{"):
            raise Unsupported("KQL nested-field queries are not translated")
        if self.peek()[0] == "op" and self.peek()[1] in ("<", "<=", ">", ">="):
            op = {"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[self.take()[1]]
            value = self.take()[1]
            return {"field": field, "op": op, "values": [_number(value)]}
        self.expect("op", ":")
        return self.value_expr(field)

    def value_expr(self, field: str) -> dict[str, Any]:
        if self.accept("op", "("):
            node = self.value_or(field)
            self.expect("op", ")")
            return node
        return self.value(field)

    def value_or(self, field: str) -> dict[str, Any]:
        parts = [self.value_and(field)]
        while self.accept("kw", "or"):
            parts.append(self.value_and(field))
        return _merge_any(parts)

    def value_and(self, field: str) -> dict[str, Any]:
        parts = [self.value_not(field)]
        while self.accept("kw", "and"):
            parts.append(self.value_not(field))
        return parts[0] if len(parts) == 1 else {"all": parts}

    def value_not(self, field: str) -> dict[str, Any]:
        if self.accept("kw", "not"):
            return {"not": self.value_not(field)}
        if self.accept("op", "("):
            node = self.value_or(field)
            self.expect("op", ")")
            return node
        return self.value(field)

    def value(self, field: str) -> dict[str, Any]:
        kind, text = self.take()
        text_field = field in TEXT_FIELDS
        if kind == "str":
            literal = _unescape_string(text)
            if text_field:
                return {"field": field, "op": "phrase", "values": [literal]}
            return {"field": field, "op": "eq", "values": [literal], "ci": field.endswith(".caseless")}
        if kind != "word":
            raise Unsupported(f"KQL: expected a value for {field}, found {text!r}")
        if text == "*":
            return {"field": field, "op": "exists"}
        pattern, wild = _unescape_word(text)
        if text_field:
            if wild and ESCAPED_STAR in pattern:
                raise Unsupported("KQL wildcard value with an escaped '*' cannot be expressed exactly")
            return {"field": field, "op": "token_wildcard" if wild else "phrase",
                    "values": [pattern.replace(ESCAPED_STAR, "*")]}
        if pattern.lower() in ("true", "false") and not wild:
            return {"field": field, "op": "eq", "values": [pattern.lower() == "true"]}
        if wild:
            return {"field": field, "op": "wildcard", "values": [_wild(pattern)], "ci": field.endswith(".caseless"),
                    "star_only": True}
        return {"field": field, "op": "eq", "values": [pattern.replace(ESCAPED_STAR, "*")], "ci": field.endswith(".caseless")}


def _wild(pattern: str) -> str:
    # KQL wildcards: only '*' is special ('?' is literal; the node carries star_only=True).
    if ESCAPED_STAR in pattern:
        raise Unsupported("KQL wildcard value with an escaped '*' cannot be expressed exactly")
    return pattern


def _number(text: str) -> float | int:
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError as error:
            raise Unsupported(f"KQL range on a non-number {text!r}") from error


def _merge_any(parts: list[dict[str, Any]]) -> dict[str, Any]:
    if len(parts) == 1:
        return parts[0]
    # Fold "field : (a or b or c*)" into one leaf per operator for speed.
    simple = all("field" in p and p.get("op") in ("eq", "wildcard", "phrase", "token_wildcard") for p in parts)
    if simple and len({(p["field"], p["op"], bool(p.get("ci")), bool(p.get("star_only"))) for p in parts}) == 1:
        first = parts[0]
        return {**first, "values": [v for p in parts for v in p["values"]]}
    if simple:
        groups: dict[tuple, dict[str, Any]] = {}
        for p in parts:
            key = (p["field"], p["op"], bool(p.get("ci")), bool(p.get("star_only")))
            groups.setdefault(key, {**p, "values": []})["values"].extend(p["values"])
        return {"any": list(groups.values())}
    return {"any": parts}


def parse(text: str) -> dict[str, Any]:
    node = Parser(text).parse()
    return _rename_caseless(node)


def _rename_caseless(node: dict[str, Any]) -> dict[str, Any]:
    for key in ("all", "any"):
        if key in node:
            return {key: [_rename_caseless(child) for child in node[key]]}
    if "not" in node:
        return {"not": _rename_caseless(node["not"])}
    if node.get("field", "").endswith(".caseless"):
        return {**node, "field": node["field"][:-9], "ci": True}
    return node
