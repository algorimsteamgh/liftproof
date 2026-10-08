"""Correlation: values the server generates that a later step reuses (spec 6).

Detection runs at record time, in memory, before bodies are reduced to hashes. A
candidate is a value found in a response (a JSON leaf, a hidden form field or CSRF meta
tag, a Location header) that reappears in a later request or step. Short or low entropy
candidates are recorded unconfirmed: the engineer confirms them, they are never applied
silently.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, quote_plus

from liftproof.web.journey import Correlation

MIN_LENGTH = 3
CONFIRM_BITS = 16.0  # total Shannon entropy needed to apply a correlation unconfirmed


def entropy_bits(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values()) * n


def confident(value: str) -> bool:
    """Long enough and varied enough that reappearing later is no coincidence."""
    has_digit = any(c.isdigit() for c in value)
    return (len(value) >= 5 and has_digit) or (
        len(value) >= 12 and entropy_bits(value) >= CONFIRM_BITS
    )


def json_leaves(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from json_leaves(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from json_leaves(v, f"{path}[{i}]")
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float, str)):
        yield path, str(value)


_STEP = re.compile(r"\.([^.\[\]]+)|\[(\d+)\]")


def json_get(value: Any, path: str) -> Any:
    if not path.startswith("$"):
        return None
    for key, index in _STEP.findall(path[1:]):
        try:
            value = value[int(index)] if index else value[key]
        except (KeyError, IndexError, TypeError):
            return None
    return value


class _FormFields(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "input" and a.get("type", "").lower() == "hidden" and a.get("name"):
            self.fields[a["name"]] = a.get("value", "")
        elif tag == "meta" and re.search(r"csrf|xsrf|nonce", a.get("name", ""), re.I):
            self.fields[a["name"]] = a.get("content", "")


def form_fields(html: str) -> dict[str, str]:
    p = _FormFields()
    try:
        p.feed(html)
    except Exception:  # noqa: S110 - malformed markup yields what was parsed
        pass
    return p.fields


def extract(
    extractor: str, expression: str, *, json: Any, body: bytes | None, headers: dict[str, str]
) -> str | None:
    match extractor:
        case "json_path":
            v = json_get(json, expression) if json is not None else None
            return None if v is None or isinstance(v, (dict, list)) else str(v)
        case "form_field":
            if body is None:
                return None
            return form_fields(body.decode("utf-8", "replace")).get(expression)
        case "header":
            return headers.get(expression.lower())
        case "header_segment":  # "location:2" is the third path segment of Location
            name, _, index = expression.partition(":")
            segs = headers.get(name.lower(), "").split("?")[0].split("/")
            return segs[int(index)] if index.isdigit() and int(index) < len(segs) else None
        case "regex":
            if body is None:
                return None
            m = re.search(expression, body.decode("utf-8", "replace"))
            return m.group(1) if m and m.groups() else (m.group(0) if m else None)
    return None


def _forms(value: str) -> set[str]:
    return {value, quote(value, safe=""), quote_plus(value)}


def _name(path_or_field: str, endpoint: str, taken: set[str]) -> str:
    base = re.sub(r"\[\d+\]", "", path_or_field).split(".")[-1].lstrip("$") or "value"
    resource = [s for s in endpoint.split(" ", 1)[-1].split("/") if s and "{" not in s]
    stem = f"{resource[-1]}.{base}" if resource and base in ("id", "value") else base
    name, i = stem, 2
    while name in taken:
        name, i = f"{stem}{i}", i + 1
    taken.add(name)
    return name


def detect(
    steps_traffic: list[list[dict[str, Any]]], later_text: list[list[str]]
) -> list[Correlation]:
    """steps_traffic[n]: captured exchanges of step n as dicts with endpoint, json, body,
    headers, request_text. later_text[n]: text the engineer's step n sent (URL, value).

    A value is a candidate when it appears in a response of step i and in the request
    text of a step after i (or a later request within step i).
    """
    found: list[Correlation] = []
    seen_values: set[str] = set()
    taken: set[str] = set()
    for i, traffic in enumerate(steps_traffic):
        for j, ex in enumerate(traffic):
            sources: list[tuple[str, str, str]] = []
            if ex.get("json") is not None:
                sources += [("json_path", p, v) for p, v in json_leaves(ex["json"])]
            ctype = ex.get("content_type", "")
            if "html" in ctype and ex.get("body"):
                html = ex["body"].decode("utf-8", "replace")
                sources += [("form_field", k, v) for k, v in form_fields(html).items()]
            if "location" in ex.get("headers", {}):
                segs = ex["headers"]["location"].split("?")[0].split("/")
                sources += [
                    ("header_segment", f"location:{k}", seg)
                    for k, seg in enumerate(segs)
                    if re.fullmatch(r"[0-9]+|[0-9a-fA-F-]{8,}", seg)
                ]
            for extractor, expression, value in sources:
                if len(value) < MIN_LENGTH or value in seen_values:
                    continue
                forms = _forms(value)
                used = []
                later_requests = traffic[j + 1 :] + [x for t in steps_traffic[i + 1 :] for x in t]
                for x in later_requests:
                    if any(f in (x.get("request_text") or "") for f in forms):
                        used.append(x["endpoint"])
                for n, texts in enumerate(later_text[i + 1 :], start=i + 2):
                    if any(f in t for t in texts for f in forms):
                        used.append(f"step {n}")
                if not used:
                    continue
                seen_values.add(value)
                found.append(
                    Correlation(
                        name=_name(
                            "id" if extractor == "header_segment" else expression,
                            ex["endpoint"],
                            taken,
                        ),
                        extractor=extractor,
                        source=ex["endpoint"],
                        expression=expression,
                        recorded_value=value,
                        used_in=sorted(set(used)),
                        confirmed=confident(value),
                    )
                )
    return found
