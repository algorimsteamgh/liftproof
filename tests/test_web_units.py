"""Comparison and correlation rules that need no browser."""

from liftproof.findings import Kind
from liftproof.web import correlate
from liftproof.web.browser import normalise_path
from liftproof.web.compare import Comparison, WebOptions
from liftproof.web.journey import Correlation, Journey, shape
from liftproof.web.replay import JourneyRun


def cmp(correlations=(), values=None, **opts):
    j = Journey("j", "http://x", correlations=list(correlations))
    run = JourneyRun("j", values=values or {})
    out = []
    return Comparison(j, run, WebOptions(**opts), out.append, lambda ref: None), out


def test_numbers_compare_as_numbers():
    c, out = cmp()
    c._json("GET /a", {"total": 10.50, "n": 3, "s": "10.50"}, {"total": 10.5, "n": 3.0,
                                                                 "s": "10.5"}, "$", 1)
    assert out == []
    c._json("GET /a", {"total": 10.5}, {"total": "10.5"}, "$", 1)  # a type change is real
    assert [f.column for f in out] == ["$.total"]


def test_shape_reports_added_and_missing_fields():
    c, out = cmp()
    c._shape("GET /a", shape({"a": 1, "b": "x"}), shape({"a": 2, "c": True}), "$", 1)
    assert sorted(f.summary for f in out) == [
        "field $.b missing on the target", "field $.c added on the target"]
    assert all(f.kind == Kind.DIFFERENCE for f in out)


def test_correlated_values_are_masked_everywhere():
    corr = Correlation("orders.id", "json_path", "POST /api/orders", "$.id", "12345")
    c, out = cmp([corr], {"12345": "99999"})
    c._json("POST /api/orders", {"id": 12345}, {"id": 99999}, "$", 1)
    c._json("GET /api/orders/{orders.id}", {"id": 12345, "ref": "ord-12345"},
            {"id": 99999, "ref": "ord-99999"}, "$", 2)
    c.ui("- heading \"Order 12345\"", "- heading \"Order 99999\"", 3)
    assert out == []
    assert normalise_path("/orders/99999/items", {"99999": "orders.id"}) == \
        "/orders/{orders.id}/items"


def test_default_volatile_values_and_ignore_rules():
    c, out = cmp(ignore_text=[r"Build \w+"], ignore_json_paths=["GET /a $.etag"])
    c.ui("- text: Placed 2026-10-05T09:00:01Z Build abc", "- text: Placed 2026-10-06T10:11:12Z "
         "Build def", 1)
    c._json("GET /a", {"etag": "1"}, {"etag": "2"}, "$", 1)
    assert out == []


def test_values_hidden_unless_asked():
    c, out = cmp()
    c._json("GET /a", {"s": "secret-ish"}, {"s": "other"}, "$", 1)
    assert out[0].expected.startswith("sha256:")
    c, out = cmp(show_values=True)
    c._json("GET /a", {"s": "a"}, {"s": "b"}, "$", 1)
    assert (out[0].expected, out[0].actual) == ("a", "b")


def test_correlation_confidence_and_extractors():
    assert correlate.confident("839201") and correlate.confident("a8f0c2d9e7b14c33")
    assert not correlate.confident("1") and not correlate.confident("OPEN")
    assert correlate.json_get({"a": [{"b": 7}]}, "$.a[0].b") == 7
    html = '<form><input type="hidden" name="__VIEWSTATE" value="dDwtMTA="></form>'
    assert correlate.extract("form_field", "__VIEWSTATE", json=None, body=html.encode(),
                             headers={}) == "dDwtMTA="
    assert correlate.extract("header_segment", "location:2", json=None, body=None,
                             headers={"location": "/orders/4411?x=1"}) == "4411"


def test_detect_skips_coincidences():
    traffic = [
        [{"endpoint": "POST /api/orders", "json": {"id": 48213, "qty": 1, "status": "OPEN"},
          "body": None, "headers": {}, "content_type": "application/json",
          "request_text": "/api/orders\n{\"qty\": 1}"}],
        [{"endpoint": "GET /api/orders/{id}", "json": None, "body": None, "headers": {},
          "content_type": "", "request_text": "/api/orders/48213?status=OPEN\n"}],
    ]
    found = correlate.detect(traffic, [[""], [""]])
    assert [(c.recorded_value, c.confirmed) for c in found] == [("48213", True), ("OPEN", False)]
