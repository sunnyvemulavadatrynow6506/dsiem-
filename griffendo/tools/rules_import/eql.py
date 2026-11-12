"""Parser for the subset of Elastic EQL used by the supplied rules, translated to Griffendo conditions.

Only syntax is handled here.  Whether the translated condition can be evaluated
on local Windows event data is decided by availability.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any


class Unsupported(Exception):
    """The query uses a construct Griffendo does not translate (the message says which)."""


TOKEN = re.compile(r"""
    (?P<ws>\s+|//[^\n]*|/\*.*?\*/)
  | (?P<raw>\"\"\"(?:.|\n)*?\"\"\")
  | (?P<qraw>\?\"(?:[^"\\]|\\.)*\")
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<num>-?\d+(?:\.\d+)?(?:[smhd]\b)?)
  | (?P<op>==|!=|<=|>=|<|>|:|\(|\)|\[|\]|,|\||~|\?|=)
  | (?P<bt>`[^`]+`)
  | (?P<name>[A-Za-z_@][A-Za-z0-9_@.\-]*)
""", re.X | re.S)

KEYWORDS = {"and", "or", "not", "in", "like", "regex", "where", "sequence", "by", "with", "maxspan", "until",
            "true", "false", "null", "runs", "sample", "join", "of", "any"}


def unescape(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


@dataclass
class Tok:
    kind: str
    text: str


def tokenize(query: str) -> list[Tok]:
    tokens: list[Tok] = []
    pos = 0
    while pos < len(query):
        match = TOKEN.match(query, pos)
        if not match:
            raise Unsupported(f"EQL syntax not understood near {query[pos:pos + 30]!r}")
        pos = match.end()
        kind = match.lastgroup
        text = match.group(kind)
        if kind == "ws":
            continue
        if kind == "raw":
            tokens.append(Tok("str", text[3:-3]))
        elif kind == "qraw":
            tokens.append(Tok("str", text[2:-1]))
        elif kind == "str":
            tokens.append(Tok("str", unescape(text[1:-1])))
        elif kind == "bt":
            tokens.append(Tok("name", text[1:-1]))
        elif kind == "name" and text.lower() in KEYWORDS:
            tokens.append(Tok("kw", text.lower()))
        else:
            tokens.append(Tok(kind, text))
    tokens.append(Tok("eof", ""))
    return tokens


@dataclass
class Step:
    category: str
    expr: Any
    by: list[str] = dc_field(default_factory=list)
    runs: int = 1


@dataclass
class Query:
    kind: str                      # "event" or "sequence"
    steps: list[Step]
    by: list[str] = dc_field(default_factory=list)
    maxspan: int | None = None     # seconds
    until: Step | None = None


class Parser:
    def __init__(self, text: str):
        self.tokens = tokenize(text)
        self.i = 0

    # ---- token helpers
    def peek(self, offset: int = 0) -> Tok:
        return self.tokens[min(self.i + offset, len(self.tokens) - 1)]

    def take(self) -> Tok:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def accept(self, kind: str, text: str | None = None) -> Tok | None:
        tok = self.peek()
        if tok.kind == kind and (text is None or tok.text == text):
            self.i += 1
            return tok
        return None

    def expect(self, kind: str, text: str | None = None) -> Tok:
        tok = self.accept(kind, text)
        if tok is None:
            got = self.peek()
            raise Unsupported(f"EQL: expected {text or kind}, found {got.text!r}")
        return tok

    # ---- grammar
    def query(self) -> Query:
        if self.accept("kw", "sequence"):
            result = self.sequence()
        elif self.peek().kind == "kw" and self.peek().text in ("sample", "join"):
            raise Unsupported(f"EQL '{self.peek().text}' queries are not translated")
        else:
            result = Query("event", [self.event_query()])
        if self.accept("op", "|"):
            raise Unsupported("EQL pipes (| head, | tail, | unique ...) are not translated")
        self.expect("eof")
        return result

    def duration(self) -> int:
        tok = self.take()
        match = re.fullmatch(r"(\d+)([smhd]?)", tok.text)
        if not match:
            raise Unsupported(f"EQL: bad duration {tok.text!r}")
        value = int(match.group(1))
        unit = match.group(2) or "s"
        if not match.group(2) and self.peek().kind == "name" and self.peek().text in ("s", "m", "h", "d"):
            unit = self.take().text
        return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]

    def by_fields(self) -> list[str]:
        fields = [self.field_name()]
        while self.accept("op", ","):
            fields.append(self.field_name())
        return fields

    def field_name(self) -> str:
        self.accept("op", "?")
        tok = self.take()
        if tok.kind not in ("name", "kw"):
            raise Unsupported(f"EQL: expected a field name, found {tok.text!r}")
        return tok.text

    def sequence(self) -> Query:
        query = Query("sequence", [])
        while True:
            if self.accept("kw", "by"):
                query.by = self.by_fields()
            elif self.accept("kw", "with"):
                self.expect("kw", "maxspan")
                self.expect("op", "=")
                query.maxspan = self.duration()
            else:
                break
        while self.accept("op", "["):
            step = Step(*self._step_body())
            self.expect("op", "]")
            while True:
                if self.accept("kw", "by"):
                    step.by = self.by_fields()
                elif self.accept("kw", "with"):
                    self.expect("kw", "runs")
                    self.expect("op", "=")
                    step.runs = int(self.take().text)
                else:
                    break
            query.steps.append(step)
        if self.accept("kw", "until"):
            self.expect("op", "[")
            query.until = Step(*self._step_body())
            self.expect("op", "]")
            if self.accept("kw", "by"):
                query.until.by = self.by_fields()
        if len(query.steps) < 2 and not (query.steps and query.steps[0].runs > 1):
            raise Unsupported("EQL sequence with fewer than two steps")
        return query

    def _step_body(self) -> tuple[str, Any]:
        step = self.event_query()
        return step.category, step.expr

    def event_query(self) -> Step:
        tok = self.take()
        if tok.kind not in ("name", "kw"):
            raise Unsupported(f"EQL: expected an event category, found {tok.text!r}")
        category = tok.text.lower()
        self.expect("kw", "where")
        return Step(category, self.expr())

    def expr(self) -> Any:
        parts = [self.and_expr()]
        while self.accept("kw", "or"):
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self) -> Any:
        parts = [self.not_expr()]
        while self.accept("kw", "and"):
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_expr(self) -> Any:
        if self.accept("kw", "not"):
            return ("not", self.not_expr())
        return self.comparison()

    def value_list(self) -> list[Any]:
        self.expect("op", "(")
        values = [self.term()]
        while self.accept("op", ","):
            if self.peek().kind == "op" and self.peek().text == ")":
                break
            values.append(self.term())
        self.expect("op", ")")
        return values

    def values_or_single(self) -> list[Any]:
        if self.peek().kind == "op" and self.peek().text == "(":
            return self.value_list()
        return [self.term()]

    def comparison(self) -> Any:
        left = self.term()
        tok = self.peek()
        if tok.kind == "op" and tok.text in ("==", "!=", "<", "<=", ">", ">="):
            self.take()
            return ("cmp", tok.text, left, self.term())
        if tok.kind == "op" and tok.text == ":":
            self.take()
            return ("match", left, self.values_or_single())
        negate = False
        if tok.kind == "kw" and tok.text == "not" and self.peek(1).kind == "kw" and self.peek(1).text == "in":
            self.take()
            negate = True
            tok = self.peek()
        if tok.kind == "kw" and tok.text in ("in", "like", "regex"):
            self.take()
            ci = bool(self.accept("op", "~"))
            values = self.values_or_single()
            node = (tok.text, left, values, ci)
            return ("not", node) if negate else node
        return left if not (isinstance(left, tuple) and left[0] in ("field", "lit", "func")) else ("truthy", left) \
            if left[0] == "func" else left

    def term(self) -> Any:
        tok = self.peek()
        if tok.kind == "op" and tok.text == "(":
            self.take()
            inner = self.expr()
            self.expect("op", ")")
            return inner
        if tok.kind == "op" and tok.text == "?":
            self.take()
            return ("field", self.take().text)
        if tok.kind == "str":
            self.take()
            return ("lit", tok.text)
        if tok.kind == "num":
            self.take()
            text = tok.text
            return ("lit", float(text) if "." in text else int(text))
        if tok.kind == "kw" and tok.text in ("true", "false"):
            self.take()
            return ("lit", tok.text == "true")
        if tok.kind == "kw" and tok.text == "null":
            self.take()
            return ("null",)
        if tok.kind in ("name", "kw"):
            self.take()
            ci = False
            if self.peek().kind == "op" and self.peek().text == "~" and self.peek(1).text == "(":
                self.take()
                ci = True
            if self.peek().kind == "op" and self.peek().text == "(":
                self.take()
                args = []
                if not self.accept("op", ")"):
                    args.append(self.expr())
                    while self.accept("op", ","):
                        args.append(self.expr())
                    self.expect("op", ")")
                return ("func", tok.text, ci, args)
            return ("field", tok.text)
        raise Unsupported(f"EQL: unexpected {tok.text!r}")


def parse(text: str) -> Query:
    return Parser(text).query()


# ------------------------------------------------------------------------------------------- translation
def _field(node: Any) -> tuple[str, bool]:
    if not (isinstance(node, tuple) and node[0] == "field"):
        raise Unsupported(f"EQL comparison whose left side is not a field ({node!r:.60})")
    name = node[1]
    if name.endswith(".caseless"):
        return name[:-9], True
    return name, False


def _literal(node: Any) -> Any:
    if isinstance(node, tuple) and node[0] == "lit":
        return node[1]
    raise Unsupported(f"EQL value that is not a literal ({node!r:.60})")


def _has_wildcard(value: Any) -> bool:
    return isinstance(value, str) and ("*" in value or "?" in value)


def translate_expr(node: Any) -> dict[str, Any]:
    kind = node[0]
    if kind == "and":
        return {"all": [translate_expr(child) for child in node[1]]}
    if kind == "or":
        return {"any": [translate_expr(child) for child in node[1]]}
    if kind == "not":
        return {"not": translate_expr(node[1])}
    if kind == "match":                       # field : value(s)   (case-insensitive, wildcards allowed)
        field, _ = _field(node[1])
        values = [_literal(v) for v in node[2]]
        if any(isinstance(v, bool) for v in values) or all(isinstance(v, (int, float)) for v in values):
            return {"field": field, "op": "eq", "values": values, "ci": True}
        if any(_has_wildcard(v) for v in values):
            return {"field": field, "op": "wildcard", "values": [str(v) for v in values], "ci": True}
        return {"field": field, "op": "eq", "values": values, "ci": True}
    if kind in ("in", "match") and any(isinstance(v, tuple) and v[0] == "field" for v in node[2]):
        field, ci_field = _field(node[1])
        ci = kind == "match" or (len(node) > 3 and node[3]) or ci_field
        parts = []
        for value in node[2]:
            if isinstance(value, tuple) and value[0] == "field":
                parts.append({"field": field, "op": "eq_field", "other": _field(value)[0], "ci": bool(ci)})
            else:
                parts.append({"field": field, "op": "eq", "values": [_literal(value)], "ci": bool(ci)})
        return parts[0] if len(parts) == 1 else {"any": parts}
    if kind in ("in", "like", "regex"):
        field, ci_field = _field(node[1])
        values = [_literal(v) for v in node[2]]
        ci = node[3] or ci_field
        op = {"in": "eq", "like": "wildcard", "regex": "regex"}[kind]
        return {"field": field, "op": op, "values": values, "ci": ci}
    if kind == "cmp":
        op, left, right = node[1], node[2], node[3]
        if isinstance(left, tuple) and left[0] == "func":
            return _function_cmp(left, op, right)
        if isinstance(left, tuple) and left[0] == "lit" and isinstance(right, tuple) and right[0] == "field":
            left, right = right, left
            op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)
        field, ci = _field(left)
        if isinstance(right, tuple) and right[0] == "null":
            exists = {"field": field, "op": "exists"}
            return {"not": exists} if op == "==" else exists
        if isinstance(right, tuple) and right[0] == "field":
            other, _ = _field(right)
            if op not in ("==", "!="):
                raise Unsupported("EQL ordering comparison between two fields")
            return {"field": field, "op": "eq_field" if op == "==" else "ne_field", "other": other, "ci": ci}
        value = _literal(right)
        if op in ("==", "!="):
            leaf = {"field": field, "op": "eq", "values": [value], "ci": ci}
            return leaf if op == "==" else {"not": leaf}
        return {"field": field, "op": {"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[op], "values": [value]}
    if kind == "func":
        return _function_bool(node)
    if kind in ("field", "lit"):
        if kind == "lit" and isinstance(node[1], bool):
            return {"const": node[1]}
        raise Unsupported(f"EQL bare value used as a condition ({node!r:.60})")
    if kind == "truthy":
        inner = node[1]
        if isinstance(inner, tuple) and inner[0] == "func":
            return _function_bool(inner)
        if isinstance(inner, tuple) and inner[0] == "lit" and isinstance(inner[1], bool):
            return {"const": inner[1]}
        if isinstance(inner, tuple) and inner[0] in ("and", "or", "not", "match", "in", "like", "regex", "cmp"):
            return translate_expr(inner)
        raise Unsupported(f"EQL bare value used as a condition ({inner!r:.60})")
    raise Unsupported(f"EQL construct {kind!r}")


def _function_bool(node: Any) -> dict[str, Any]:
    _, name, ci, args = node
    lname = name.lower()
    if lname in ("startswith", "endswith", "stringcontains"):
        field, ci_field = _field(args[0])
        values = [_literal(arg) for arg in args[1:]]
        op = {"startswith": "startswith", "endswith": "endswith", "stringcontains": "contains"}[lname]
        return {"field": field, "op": op, "values": values, "ci": ci or ci_field}
    if lname == "cidrmatch":
        field, _ = _field(args[0])
        return {"field": field, "op": "cidr", "values": [_literal(arg) for arg in args[1:]]}
    if lname == "match":
        field, _ = _field(args[0])
        return {"field": field, "op": "regex", "values": [_literal(arg) for arg in args[1:]], "ci": ci}
    raise Unsupported(f"EQL function {name}() is not translated")


def _function_cmp(func: Any, op: str, right: Any) -> dict[str, Any]:
    _, name, _ci, args = func
    if name.lower() == "length" and len(args) == 1:
        field, _ = _field(args[0])
        cmp = {"==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[op]
        return {"fn": "length", "field": field, "op": cmp, "value": _literal(right)}
    raise Unsupported(f"EQL function {name}() in a comparison is not translated")
