"""Correlation: values the server generates that a later step reuses (spec 6).

Detection runs at record time, in memory, before bodies are reduced to hashes. A
candidate is a value found in a response (a JSON leaf, a hidden form field or CSRF meta
tag, a Location header) that reappears in a later request or step. Short or low entropy
candidates are recorded unconfirmed: the engineer confirms them, they are never applied
silently.

Transform chains: a value can be sent encoded and used decoded (a base64 reference that
carries an order id, a URL encoded token), or sent plain and used encoded (an id that a
later URL carries base64 or URL encoded). The first is a correlation's transforms, the
decoding applied after extraction; the second its encodings, the other forms replaced
when the value is substituted and masked when responses are compared.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, quote_plus, unquote

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


# --------------------------------------------------------------- transform chains
_B64 = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_B64URL = re.compile(r"[A-Za-z0-9_-]{8,}={0,2}")


def _text(raw: bytes) -> str | None:
    """Decoded bytes as text, when they are text a person or a program would reuse."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and text.isprintable() else None


def decode(name: str, value: str) -> str | None:
    """One decoding step; None when the value is not in that form."""
    match name:
        case "url_decode":
            return unquote(value, errors="strict") if "%" in value else None
        case "base64_decode" | "base64url_decode":
            pattern = _B64 if name == "base64_decode" else _B64URL
            if not pattern.fullmatch(value):
                return None
            padded = value + "=" * (-len(value) % 4)
            try:
                raw = (
                    base64.b64decode(padded, validate=True)
                    if name == "base64_decode"
                    else base64.urlsafe_b64decode(padded)
                )
            except (binascii.Error, ValueError):
                return None
            return _text(raw)
    raise ValueError(f"unknown transform {name!r}")


def encode(name: str, value: str) -> str:
    match name:
        case "url":
            return quote(value, safe="")
        case "url_plus":
            return quote_plus(value)
        case "base64":
            return base64.b64encode(value.encode()).decode()
        case "base64url":
            return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    raise ValueError(f"unknown encoding {name!r}")


TRANSFORMS = ("url_decode", "base64_decode", "base64url_decode")
ENCODINGS = ("url", "url_plus", "base64", "base64url")
_INVERSE = {"url_decode": "url", "base64_decode": "base64", "base64url_decode": "base64url"}


def check_chain(transforms: Sequence[str], encodings: Sequence[str]) -> None:
    for t in transforms:
        if t not in TRANSFORMS:
            raise ValueError(f"unknown transform {t!r}; use one of {', '.join(TRANSFORMS)}")
    for e in encodings:
        if e not in ENCODINGS:
            raise ValueError(f"unknown encoding {e!r}; use one of {', '.join(ENCODINGS)}")


def apply(transforms: Sequence[str], value: str | None) -> str | None:
    """The extracted value through its decoding chain; None if a step does not apply."""
    for t in transforms:
        if value is None:
            return None
        value = decode(t, value)
    return value


def forms(c: Correlation, value: str) -> dict[str, str]:
    """Every form a correlated value takes, value included: the encodings later steps
    use, and the encoded form the server sent before the transforms decoded it."""
    out = {encode(e, value): e for e in c.encodings}
    raw = value
    for t in reversed(c.transforms):
        raw = encode(_INVERSE[t], raw)
    out.setdefault(raw, "source")  # a later step may reuse it as sent: then it is replaced
    out[value] = ""
    return out


def _decoded(value: str) -> Iterator[tuple[list[str], str]]:
    """The value's decoded forms with the chain that produced them, one or two steps
    deep (base64 inside a URL encoded parameter)."""
    for first in TRANSFORMS:
        d = decode(first, value)
        if d is None or d == value:
            continue
        yield [first], d
        for second in TRANSFORMS:
            d2 = decode(second, d)
            if d2 is not None and d2 != d:
                yield [first, second], d2


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


def _used_forms(value: str) -> dict[str, str]:
    """form -> encoding name ('' for the value as it is)."""
    out: dict[str, str] = {}
    for e in reversed(ENCODINGS):
        out[encode(e, value)] = e
    out[value] = ""
    return out


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
            later_requests = traffic[j + 1 :] + [x for t in steps_traffic[i + 1 :] for x in t]
            for extractor, expression, sent in sources:
                if len(sent) < MIN_LENGTH or sent in seen_values:
                    continue
                # the value as sent first; its decoded forms only when it is not reused
                # as it is
                hit = next(
                    (
                        (transforms, value, *uses)
                        for transforms, value in [([], sent), *_decoded(sent)]
                        if len(value) >= MIN_LENGTH
                        for uses in [_uses(value, later_requests, later_text, i)]
                        if uses[0]
                    ),
                    None,
                )
                if hit is None:
                    continue
                transforms, value, used, encodings = hit
                seen_values.add(sent)
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
                        transforms=transforms,
                        encodings=encodings,
                    )
                )
    return found


def _uses(
    value: str, later_requests: list[dict[str, Any]], later_text: list[list[str]], i: int
) -> tuple[list[str], list[str]]:
    """Where the value reappears after step i (endpoints and steps), and the encodings
    it reappears in besides its plain form."""
    candidates = _used_forms(value)
    used: list[str] = []
    seen: set[str] = set()
    for x in later_requests:
        text = x.get("request_text") or ""
        hit = [e for f, e in candidates.items() if f in text]
        if hit:
            used.append(x["endpoint"])
            seen.update(hit)
    for n, texts in enumerate(later_text[i + 1 :], start=i + 2):
        hit = [e for f, e in candidates.items() if any(f in t for t in texts)]
        if hit:
            used.append(f"step {n}")
            seen.update(hit)
    if {"base64", "base64url"} <= seen and encode("base64url", value) == encode(
        "base64", value
    ).rstrip("="):
        seen.discard("base64url")  # the same characters: base64url only lacks the padding
    return used, [e for e in ENCODINGS if e in seen]
