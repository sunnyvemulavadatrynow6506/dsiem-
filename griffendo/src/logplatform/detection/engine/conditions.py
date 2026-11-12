"""Safe condition language for detection rules.

Rules (imported, built-in and user-created) describe their conditions as plain
JSON-compatible data; nothing is ``eval``'d and no user code runs.  This module
validates a condition tree, compiles it into a Python predicate over a
normalized event, and can produce a *witness* event that satisfies it (used by
the test suite to prove every translated rule can fire).

Grammar::

    node := {"all": [node, ...]} | {"any": [node, ...]} | {"not": node} | {"const": bool}
          | {"field": F, "op": OP, "values": [...], "ci": bool}
          | {"field": F, "op": "exists"}
          | {"field": F, "op": "eq_field" | "ne_field", "other": F2, "ci": bool}
          | {"fn": "length" | "regex_count" | "count_chars", "field": F, "op": CMP, "value": number,
             "pattern": str (regex_count) | "chars": str (count_chars), "ratio": bool}

    OP  := eq | wildcard | regex | contains | startswith | endswith | gt | gte | lt | lte | cidr
         | phrase | token_wildcard     (Elasticsearch *text* field semantics: case-insensitive word tokens)
    CMP := eq | ne | gt | gte | lt | lte

Semantics follow Elasticsearch, which both rule sources were written for:
a predicate on a missing field is false; ``not`` is plain negation (so an
exclusion on a missing field does not exclude); on a multi-valued field
(``process.args``, ``registry.data.strings``) a predicate is true when any
element matches.  ``ci`` makes string comparisons case-insensitive.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from typing import Any, Callable

from .normalizer import get

Predicate = Callable[[dict[str, Any]], bool]
OPS = {"eq", "wildcard", "regex", "contains", "startswith", "endswith", "gt", "gte", "lt", "lte", "cidr", "exists",
       "eq_field", "ne_field", "phrase", "token_wildcard"}
FNS = {"length", "regex_count", "count_chars"}
CMPS = {"eq", "ne", "gt", "gte", "lt", "lte"}
MAX_NODES = 2000
MAX_DEPTH = 40
MAX_PATTERN = 2000
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


class ConditionError(ValueError):
    pass


# ------------------------------------------------------------------------------------------- helpers
def wildcard_regex(pattern: str, star_only: bool = False) -> str:
    """Elasticsearch wildcard -> regular expression (``*`` any run, ``?`` one character unless ``star_only``)."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?" and not star_only:
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def _values(node: dict[str, Any]) -> list[Any]:
    values = node.get("values")
    if values is None and "value" in node:
        values = [node["value"]]
    if not isinstance(values, list):
        raise ConditionError(f"'values' must be a list for {node.get('field')}")
    return values


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_text(item) for item in value if item is not None]
    return [_text(value)]


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip()
        return float(int(text, 16)) if text.lower().startswith("0x") else float(text)
    except ValueError:
        return None


def _compare(op: str, left: float, right: float) -> bool:
    return {"eq": left == right, "ne": left != right, "gt": left > right, "gte": left >= right,
            "lt": left < right, "lte": left <= right}[op]


# ------------------------------------------------------------------------------------------- validation
def validate(node: Any, field_ok: Callable[[str], str | None] | None = None) -> list[str]:
    """Problems with a condition tree (empty list when valid).  ``field_ok`` returns an error for unknown fields."""
    errors: list[str] = []
    count = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_NODES:
            if count == MAX_NODES + 1:
                errors.append(f"Condition is too large (more than {MAX_NODES} nodes).")
            return
        if depth > MAX_DEPTH:
            errors.append("Condition is nested too deeply.")
            return
        if not isinstance(item, dict):
            errors.append("Every condition must be an object.")
            return
        if "all" in item or "any" in item:
            key = "all" if "all" in item else "any"
            children = item[key]
            if not isinstance(children, list) or not children:
                errors.append(f"'{key}' needs a non-empty list of conditions.")
                return
            for child in children:
                walk(child, depth + 1)
            return
        if "not" in item:
            walk(item["not"], depth + 1)
            return
        if "const" in item:
            if not isinstance(item["const"], bool):
                errors.append("'const' must be true or false.")
            return
        field = item.get("field")
        if not isinstance(field, str) or not re.match(r"^[A-Za-z@_][A-Za-z0-9_.@ -]{0,120}$", field):
            errors.append(f"Invalid field name: {field!r}.")
            return
        if field_ok:
            problem = field_ok(field)
            if problem:
                errors.append(problem)
        if "fn" in item:
            if item["fn"] not in FNS:
                errors.append(f"Unknown function {item['fn']!r}.")
            if item.get("op") not in CMPS:
                errors.append(f"Function comparison must be one of {sorted(CMPS)}.")
            if _number(item.get("value")) is None:
                errors.append("Function comparison needs a numeric value.")
            if item["fn"] == "regex_count":
                _check_regex(item.get("pattern"), errors)
            return
        op = item.get("op")
        if op not in OPS:
            errors.append(f"Unknown operator {op!r} for {field}.")
            return
        if op == "exists":
            return
        if op in ("eq_field", "ne_field"):
            other = item.get("other")
            if not isinstance(other, str):
                errors.append(f"'{op}' needs the other field name.")
            elif field_ok and field_ok(other):
                errors.append(field_ok(other))
            return
        try:
            values = _values(item)
        except ConditionError as error:
            errors.append(str(error))
            return
        if not values:
            errors.append(f"No values given for {field}.")
        if len(values) > 5000:
            errors.append(f"Too many values for {field}.")
        for value in values:
            if op in ("gt", "gte", "lt", "lte") and _number(value) is None:
                errors.append(f"'{op}' on {field} needs numbers, got {value!r}.")
            elif op == "regex":
                _check_regex(value, errors)
            elif op == "cidr":
                try:
                    ipaddress.ip_network(str(value), strict=False)
                except ValueError:
                    errors.append(f"Invalid CIDR range {value!r}.")
            elif not isinstance(value, (str, int, float, bool)):
                errors.append(f"Values must be text or numbers ({field}).")
            elif isinstance(value, str) and len(value) > MAX_PATTERN:
                errors.append(f"A value for {field} is too long.")

    walk(node, 0)
    return errors


def _check_regex(pattern: Any, errors: list[str]) -> None:
    if not isinstance(pattern, str) or not pattern:
        errors.append("A regular expression is empty or not text.")
        return
    if len(pattern) > MAX_PATTERN:
        errors.append("A regular expression is too long.")
        return
    if _NESTED_QUANTIFIER.search(pattern):
        errors.append(f"Regular expression {pattern[:60]!r} nests quantifiers (catastrophic backtracking risk).")
        return
    try:
        re.compile(pattern)
    except re.error as error:
        errors.append(f"Invalid regular expression {pattern[:60]!r}: {error}.")


# ------------------------------------------------------------------------------------------- compiler
# v5.1: the same test appears in hundreds of rules (``winlog.channel is Security``, ``event.code is
# 4688`` ...).  Identical leaves compile to one shared function that remembers its result for the
# event being evaluated (in the event's private "_m" dict, created by the normalizer), so each
# distinct test runs once per event instead of once per rule.  Events built elsewhere (tests, tools)
# have no "_m" and are evaluated directly.
_LEAVES: dict[str, Predicate] = {}
_LEAVES_LOCK = __import__("threading").Lock()


def _shared_leaf(node: dict[str, Any], build) -> Predicate:
    try:
        key = json.dumps(node, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return build()
    with _LEAVES_LOCK:
        cached = _LEAVES.get(key)
        if cached is not None:
            return cached
        inner = build()
        slot = len(_LEAVES)

        def leaf(ev: dict[str, Any], _inner=inner, _slot=slot) -> bool:
            memo = ev.get("_m")
            if memo is None:
                return _inner(ev)
            result = memo.get(_slot)
            if result is None:
                result = memo[_slot] = _inner(ev)
            return result
        _LEAVES[key] = leaf
        return leaf


def compile_condition(node: dict[str, Any]) -> Predicate:
    if "field" in node:
        return _shared_leaf(node, lambda: _compile_leaf(node))
    if "all" in node:
        parts = tuple(compile_condition(child) for child in node["all"])
        if len(parts) == 1:
            return parts[0]

        def conjunction(ev: dict[str, Any], _parts=parts) -> bool:   # plain loop: no generator per call
            for part in _parts:
                if not part(ev):
                    return False
            return True
        return conjunction
    if "any" in node:
        parts = tuple(compile_condition(child) for child in node["any"])
        if len(parts) == 1:
            return parts[0]

        def disjunction(ev: dict[str, Any], _parts=parts) -> bool:
            for part in _parts:
                if part(ev):
                    return True
            return False
        return disjunction
    if "not" in node:
        inner = compile_condition(node["not"])
        return lambda ev: not inner(ev)
    if "const" in node:
        constant = bool(node["const"])
        return lambda ev: constant
    return _compile_leaf(node)


def _compile_leaf(node: dict[str, Any]) -> Predicate:
    field = node["field"]
    if "fn" in node:
        return _compile_fn(node)
    op = node["op"]
    ci = bool(node.get("ci"))
    if op == "exists":
        return lambda ev: get(ev, field) is not None
    if op in ("eq_field", "ne_field"):
        other = node["other"]
        want_equal = op == "eq_field"

        def compare_fields(ev: dict[str, Any]) -> bool:
            left, right = get(ev, field), get(ev, other)
            if left is None or right is None:
                return False
            a, b = _text(left), _text(right)
            if ci:
                a, b = a.casefold(), b.casefold()
            return (a == b) == want_equal
        return compare_fields
    values = _values(node)
    if op in ("gt", "gte", "lt", "lte"):
        bound = _number(values[0])

        def numeric(ev: dict[str, Any]) -> bool:
            value = get(ev, field)
            items = value if isinstance(value, list) else [value]
            for item in items:
                number = _number(item)
                if number is not None and bound is not None and _compare(op, number, bound):
                    return True
            return False
        return numeric
    if op == "cidr":
        networks = [ipaddress.ip_network(str(value), strict=False) for value in values]

        def in_cidr(ev: dict[str, Any]) -> bool:
            for item in _strings(get(ev, field)):
                try:
                    address = ipaddress.ip_address(item.split("%", 1)[0])
                except ValueError:
                    continue
                if any(address.version == network.version and address in network for network in networks):
                    return True
            return False
        return in_cidr
    if op == "eq":
        wanted = {(_text(value).casefold() if ci else _text(value)) for value in values}

        def equals(ev: dict[str, Any]) -> bool:
            value = get(ev, field)
            if value is None:
                return False
            if value.__class__ is str:                     # the common case, without the generic path
                return (value.casefold() if ci else value) in wanted
            if isinstance(value, list):
                return any((_text(item).casefold() if ci else _text(item)) in wanted for item in value)
            return (_text(value).casefold() if ci else _text(value)) in wanted
        return equals
    flags = re.DOTALL | (re.IGNORECASE if ci else 0)
    if op in ("phrase", "token_wildcard"):
        regex = re.compile("|".join(phrase_regex(_text(v), op == "token_wildcard") for v in values), re.IGNORECASE)
        search = regex.search

        def token_match(ev: dict[str, Any]) -> bool:
            value = get(ev, field)
            if value is None:
                return False
            if isinstance(value, list):
                return any(search(_text(item)) is not None for item in value)
            return search(_text(value)) is not None
        return token_match
    if op == "wildcard":
        star_only = bool(node.get("star_only"))
        regex = re.compile(r"\A(?:" + "|".join(wildcard_regex(_text(v), star_only) for v in values) + r")\Z", flags)
    elif op == "regex":
        # Lucene/EQL regular expressions match the whole value.
        regex = re.compile(r"\A(?:" + "|".join(f"(?:{_text(v)})" for v in values) + r")\Z", flags)
    elif op == "contains":
        regex = re.compile("|".join(re.escape(_text(v)) for v in values), flags)
    elif op == "startswith":
        regex = re.compile(r"\A(?:" + "|".join(re.escape(_text(v)) for v in values) + ")", flags)
    elif op == "endswith":
        regex = re.compile("(?:" + "|".join(re.escape(_text(v)) for v in values) + r")\Z", flags)
    else:  # pragma: no cover - validated earlier
        raise ConditionError(op)
    match = regex.match if op in ("wildcard", "regex", "startswith") else regex.search

    def text_match(ev: dict[str, Any]) -> bool:
        value = get(ev, field)
        if value is None:
            return False
        if isinstance(value, list):
            return any(match(_text(item)) is not None for item in value)
        return match(_text(value)) is not None
    return text_match


_WORD = re.compile(r"\w+")


def phrase_regex(text: str, wildcard: bool = False) -> str:
    """Regex for an Elasticsearch phrase over standard-analyzer word tokens (``\\w+``, case-insensitive)."""
    if wildcard:
        parts = [part for part in re.split(r"[^\w*?]+", text) if part]
        tokens = ["".join(r"\w*" if ch == "*" else (r"\w" if ch == "?" else re.escape(ch)) for ch in part)
                  for part in parts]
    else:
        tokens = [re.escape(token) for token in _WORD.findall(text)]
    if not tokens:
        return r"(?!x)x"
    return r"(?<!\w)" + r"\W+".join(tokens) + r"(?!\w)"


def _compile_fn(node: dict[str, Any]) -> Predicate:
    field, op, bound = node["field"], node["op"], float(node["value"])
    fn = node["fn"]
    pattern = re.compile(node["pattern"], re.DOTALL | (re.IGNORECASE if node.get("ci") else 0)) \
        if fn == "regex_count" else None
    chars = set(node.get("chars") or "")
    ratio = bool(node.get("ratio"))

    def evaluate(ev: dict[str, Any]) -> bool:
        value = get(ev, field)
        if value is None:
            return False
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = _text(item)
            if fn == "length":
                measured = float(len(text))
            elif fn == "regex_count":
                measured = float(sum(1 for _ in pattern.finditer(text)))
            else:
                measured = float(sum(1 for ch in text if ch in chars))
            if ratio:
                measured = measured / len(text) if text else 0.0
            if _compare(op, measured, bound):
                return True
        return False
    return evaluate


def describe(node: dict[str, Any]) -> str:
    """Short human-readable text for one leaf."""
    if "fn" in node:
        extra = f" /{node['pattern']}/" if node.get("pattern") else ""
        return f"{node['fn']}({node['field']}{extra}) {node['op']} {node['value']}"
    op = node.get("op")
    if op == "exists":
        return f"{node['field']} is present"
    if op in ("eq_field", "ne_field"):
        return f"{node['field']} {'=' if op == 'eq_field' else '≠'} {node['other']}"
    values = _values(node)
    shown = ", ".join(repr(v) for v in values[:4]) + (f" (+{len(values) - 4} more)" if len(values) > 4 else "")
    label = {"eq": "is", "wildcard": "matches", "regex": "matches regex", "contains": "contains",
             "startswith": "starts with", "endswith": "ends with", "gt": ">", "gte": "≥", "lt": "<", "lte": "≤",
             "cidr": "in", "phrase": "contains phrase", "token_wildcard": "contains word matching"}.get(op, op)
    return f"{node['field']} {label} {shown}" + (" (case-insensitive)" if node.get("ci") else "")


def explain(node: dict[str, Any], ev: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """The positive leaf conditions that are true for this event (what made the rule match)."""
    found: list[dict[str, Any]] = []

    def walk(item: dict[str, Any], negated: bool) -> None:
        if len(found) >= limit:
            return
        for key in ("all", "any"):
            if key in item:
                for child in item[key]:
                    walk(child, negated)
                return
        if "not" in item:
            walk(item["not"], not negated)
            return
        if "const" in item or negated:
            return
        try:
            if compile_condition(item)(ev):
                value = get(ev, item["field"])
                if isinstance(value, str) and len(value) > 300:
                    value = value[:300] + "…"
                found.append({"condition": describe(item), "value": value})
        except Exception:  # explanation must never break detection
            return
    walk(node, False)
    return found


def fields_used(node: dict[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(item: dict[str, Any]) -> None:
        for key in ("all", "any"):
            if key in item:
                for child in item[key]:
                    walk(child)
                return
        if "not" in item:
            walk(item["not"])
        elif "field" in item:
            found.add(item["field"])
            if item.get("other"):
                found.add(item["other"])
    walk(node)
    return found


def literal_values(node: dict[str, Any], field: str, positive_only: bool = True) -> set[str] | None:
    """Values a field must take for the node to be true (None when unconstrained).

    Used to index rules by Event ID / process name: a rule is only evaluated for
    events whose value is in the returned set.  Only constraints that are
    *required* (reachable through ``all`` from the root, or present in every
    branch of an ``any``) are returned, so the index never hides a match.
    """
    if "all" in node:
        result: set[str] | None = None
        for child in node["all"]:
            values = literal_values(child, field, positive_only)
            if values is not None:
                result = values if result is None else (result & values)
        return result
    if "any" in node:
        union: set[str] = set()
        for child in node["any"]:
            values = literal_values(child, field, positive_only)
            if values is None:
                return None
            union |= values
        return union
    if "not" in node or "const" in node:
        return None
    if node.get("field") == field and node.get("op") == "eq" and "fn" not in node:
        return {(_text(v).casefold() if node.get("ci") else _text(v)) for v in _values(node)}
    return None


# ------------------------------------------------------------------------------------------- witnesses
def _regex_sample(pattern: str) -> str | None:
    """A string matching ``pattern`` (simple constructs only; None when unsure)."""
    try:
        import re._parser as sre_parse  # type: ignore[import-not-found]
        import re._constants as c  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        return None
    try:
        tree = sre_parse.parse(pattern)
    except re.error:
        return None

    def build(items) -> str | None:
        out = []
        for op, arg in items:
            if op is c.LITERAL:
                out.append(chr(arg))
            elif op is c.NOT_LITERAL:
                out.append("x" if chr(arg) != "x" else "y")
            elif op is c.ANY:
                out.append("x")
            elif op is c.IN:
                ch = None
                negate = any(o is c.NEGATE for o, _ in arg)
                for o, a in arg:
                    if o is c.LITERAL:
                        ch = chr(a)
                        break
                    if o is c.RANGE:
                        ch = chr(a[0])
                        break
                    if o is c.CATEGORY:
                        ch = {c.CATEGORY_DIGIT: "1", c.CATEGORY_SPACE: " ", c.CATEGORY_WORD: "a",
                              c.CATEGORY_NOT_DIGIT: "a", c.CATEGORY_NOT_SPACE: "a", c.CATEGORY_NOT_WORD: "-"}.get(a, "a")
                        break
                if negate:
                    ch = "§"
                if ch is None:
                    return None
                out.append(ch)
            elif op in (c.MAX_REPEAT, c.MIN_REPEAT, getattr(c, "POSSESSIVE_REPEAT", None)):
                low, _high, sub = arg
                part = build(sub)
                if part is None:
                    return None
                out.append(part * max(low, 1))
            elif op is c.SUBPATTERN:
                part = build(arg[-1])
                if part is None:
                    return None
                out.append(part)
            elif op is c.BRANCH:
                part = build(arg[1][0])
                if part is None:
                    return None
                out.append(part)
            elif op is c.AT:
                continue
            elif op is c.CATEGORY:
                out.append({c.CATEGORY_DIGIT: "1", c.CATEGORY_SPACE: " ", c.CATEGORY_WORD: "a"}.get(arg, "a"))
            else:
                return None
        return "".join(out)
    sample = build(tree)
    if sample is None:
        return None
    return sample if re.fullmatch(pattern, sample, re.DOTALL | re.IGNORECASE) else None


_FILL = "gxq"


def _leaf_candidates(node: dict[str, Any]) -> list[dict[str, Any]]:
    field = node["field"]
    if "fn" in node:
        bound = float(node["value"])
        op = node["op"]
        if node["fn"] == "length":
            size = int(bound) + (1 if op == "gt" else 0) if op in ("gt", "gte", "eq") else 1
            return [{field: "a" * max(size, 1)}]
        if node["fn"] == "regex_count":
            sample = _regex_sample(node["pattern"])
            if sample is None or op not in ("gt", "gte", "eq"):
                return []
            times = int(bound) + (1 if op == "gt" else 0)
            return [{field: (sample + " ") * max(times, 1)}]
        if node["fn"] == "count_chars":
            chars = node.get("chars") or "a"
            if op not in ("gt", "gte", "eq"):
                return [{field: "a"}]
            if node.get("ratio"):
                return [{field: chars[0] * 50}]
            times = int(bound) + (1 if op == "gt" else 0)
            return [{field: chars[0] * max(times, 1)}]
        return []
    op = node["op"]
    if op == "exists":
        return [{field: _FILL}]
    if op in ("eq_field", "ne_field"):
        return [{field: _FILL, node["other"]: _FILL if op == "eq_field" else _FILL + "2"}]
    out = []
    for value in _values(node)[:12]:
        text = _text(value)
        if op == "eq":
            out.append({field: value})
        elif op == "wildcard":
            out.append({field: text.replace("*", _FILL) if node.get("star_only") else
                        text.replace("*", _FILL).replace("?", "C")})
        elif op == "contains":
            out.append({field: f"{_FILL} {text} {_FILL}"})
        elif op == "phrase":
            out.append({field: f"{_FILL} {text} {_FILL}"})
        elif op == "token_wildcard":
            out.append({field: f"{_FILL} " + text.replace("*", "q").replace("?", "q") + f" {_FILL}"})
        elif op == "startswith":
            out.append({field: text + _FILL})
        elif op == "endswith":
            out.append({field: _FILL + text})
        elif op == "regex":
            sample = _regex_sample(text)
            if sample is not None:
                out.append({field: sample})
        elif op in ("gt", "gte", "lt", "lte"):
            number = _number(value) or 0
            delta = {"gt": 1, "gte": 0, "lt": -1, "lte": 0}[op]
            out.append({field: int(number + delta) if float(number).is_integer() else number + delta})
        elif op == "cidr":
            network = ipaddress.ip_network(text, strict=False)
            address = next(iter(network.hosts()), network.network_address)
            out.append({field: str(address)})
    return out


LIST_FIELDS = {"process.args", "process.parent.args", "registry.data.strings", "dns.answers.data", "dns.resolved_ip",
               "event.type", "event.category"}


def _fragments(node: dict[str, Any], limit: int) -> list[dict[str, list[Any]]]:
    if "const" in node:
        return [{}] if node["const"] else []
    if "not" in node:
        return [{}]
    if "any" in node:
        out: list[dict[str, list[Any]]] = []
        for child in node["any"]:
            out.extend(_fragments(child, limit))
            if len(out) >= limit:
                break
        return out[:limit]
    if "all" in node:
        combos: list[dict[str, list[Any]]] = [{}]
        for child in node["all"]:
            options = _fragments(child, limit)
            if not options:
                return []
            merged = []
            for base in combos:
                for option in options:
                    item = {k: list(v) for k, v in base.items()}
                    for key, values in option.items():
                        bucket = item.setdefault(key, [])
                        for value in values:
                            if value not in bucket:
                                bucket.append(value)
                    merged.append(item)
                    if len(merged) >= limit:
                        break
                if len(merged) >= limit:
                    break
            combos = merged
        return combos[:limit]
    return [{k: [v]} for candidate in _leaf_candidates(node) for k, v in candidate.items()]


def witness_candidates(node: dict[str, Any], limit: int = 64) -> list[dict[str, Any]]:
    """Field assignments that may satisfy ``node`` (verify with the compiled predicate)."""
    out = []
    for fragments in _fragments(node, limit):
        variants: list[dict[str, Any]] = [{}]
        for key, values in fragments.items():
            if key in LIST_FIELDS:
                options = [values]
            elif len(values) == 1:
                options = [values[0]]
            else:
                # Several constraints on one scalar field: try them combined and one at a time.
                options = ([" ".join(str(v) for v in values)] if all(isinstance(v, str) for v in values) else []) \
                    + list(values)
            variants = [{**variant, key: option} for variant in variants for option in options][:8]
        out.extend(variants)
        if len(out) >= limit * 2:
            break
    return out


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())
