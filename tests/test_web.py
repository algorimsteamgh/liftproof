"""Record and replay end to end (PRD F1, F3, F4, F5; Technical Spec 5 to 8 and 18).

A journey is recorded against the sample shop, then replayed against a second copy of
the shop: unchanged, and deliberately changed. Ids, CSRF tokens and timestamps differ
between the two on every run, as they would between a source and its migrated target.
"""

import copy
import json

import pytest

from liftproof.errors import ConfigError
from liftproof.findings import Comparator, Kind
from liftproof.web.browser import BodyPolicy
from liftproof.web.compare import WebOptions
from liftproof.web.journey import Journey
from liftproof.web.recorder import Recorder
from liftproof.web.run import run_journeys
from tests.webapp import PASSWORD, ShopApp

pytestmark = pytest.mark.browser


def drive(s):
    s.act(lambda p: p.get_by_label("Username").fill("alice"))
    s.act(lambda p: p.get_by_label("Password").fill(PASSWORD))
    s.act(lambda p: p.get_by_role("button", name="Sign in").click())
    s.act(lambda p: p.get_by_label("Item").fill("Widget"))
    s.act(lambda p: p.get_by_role("button", name="Place order").click())


@pytest.fixture(scope="module")
def recorded(browser_available, tmp_path_factory):
    assets_dir = tmp_path_factory.mktemp("assets")
    with ShopApp() as app:
        journey, assets = Recorder(
            app.url, policy=BodyPolicy(["/api/*"]), headless=True
        ).record("checkout", start="/login", story="ORD-14", drive=drive)
    for sha, body in assets.items():
        (assets_dir / sha).write_bytes(body)
    return journey, assets_dir


def replay(journey, assets_dir, variant, *, secrets=None, timeout=10_000):
    findings = []
    with ShopApp(variant) as target:
        result = run_journeys(
            [journey],
            target_url=target.url,
            options=WebOptions(),
            emit=findings.append,
            assets_dir=lambda j: assets_dir,
            secret_values=secrets or (lambda j: {t: PASSWORD for t in j.secrets}),
            step_timeout_ms=timeout,
        )
    return result, findings


def test_recording_redacts_and_correlates(recorded):
    journey, _ = recorded
    text = json.dumps(journey.to_dict())
    assert PASSWORD not in text
    [(token, binding)] = journey.secrets.items()
    assert binding.field == "Password" and binding.arn is None
    assert [s.action for s in journey.steps] == ["goto", "fill", "fill", "click", "fill", "click"]
    assert journey.steps[2].value == token
    assert journey.steps[3].non_idempotent and journey.non_idempotent
    names = {c.name: c for c in journey.correlations}
    assert names["orders.id"].source == "POST /api/orders" and names["orders.id"].confirmed
    assert any(c.extractor == "form_field" for c in journey.correlations)  # the CSRF token
    kept = {e.url: e.body_asset for s in journey.steps for e in s.exchanges}
    assert kept["/login"] is None  # default deny: HTML documents are hash and shape only
    assert kept["/api/orders"] is not None
    roundtrip = Journey.from_dict(json.loads(text))
    assert roundtrip.to_dict() == journey.to_dict()


def test_unchanged_target_replays_clean(recorded):
    journey, assets = recorded
    result, findings = replay(journey, assets, "same")
    [j] = result.journeys
    assert j.status == "passed", [f.summary for f in findings]
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.ERROR)]
    assert result.endpoints and all(e["target_ms"] is not None for e in result.endpoints)


def test_changed_target_reports_exactly_the_changes(recorded):
    journey, assets = recorded
    result, findings = replay(journey, assets, "changed")
    assert result.journeys[0].status == "different"
    got = {(f.comparator, f.object, f.summary) for f in findings if f.kind == Kind.DIFFERENCE}
    assert (Comparator.API, "POST /api/orders", "value of $.status differs") in got
    assert (Comparator.API, "POST /api/orders", "field $.currency added on the target") in got
    assert (Comparator.UI, "checkout step 6", "page content differs after the step") in got
    assert (Comparator.UI, "checkout step 6",
            "locator degraded: the primary locator no longer matches") in got
    # ids the replay created and 10.50 against 10.5 are not differences
    assert not [f for f in findings if f.column in ("$.id", "$.total")]
    assert all(f.story == "ORD-14" for f in findings if f.kind == Kind.DIFFERENCE)


def test_unbound_secret_means_not_run(recorded):
    journey, assets = recorded

    def unbound(j):
        raise ConfigError("token not bound to a secret")

    result, findings = replay(journey, assets, "same", secrets=unbound)
    assert result.journeys[0].status == "not_run"
    assert [f.kind for f in findings] == [Kind.ERROR]


def test_missing_element_is_a_difference_and_the_journey_is_the_retry_unit(recorded):
    journey, assets = recorded
    j = copy.deepcopy(journey)
    j.steps[4].locator.candidates = [{"kind": "label", "value": "Product code"}]
    result, findings = replay(j, assets, "same", timeout=1500)
    [r] = result.journeys
    assert r.status == "different" and r.attempts == 2  # non idempotent: whole journey
    assert any(f.kind == Kind.FLAKE and f.detail.get("unit") == "journey" for f in findings)
    assert any(
        f.summary == "element the journey uses was not found on the target" for f in findings
    )


def test_ambiguous_locator_is_never_acted_on(recorded):
    journey, assets = recorded
    j = copy.deepcopy(journey)
    j.steps[1].locator.candidates = [{"kind": "css", "value": "input"}]
    result, findings = replay(j, assets, "same")
    [r] = result.journeys
    assert r.status == "failed" and r.attempts == 1
    [err] = [f for f in findings if f.kind == Kind.ERROR]
    assert err.summary.startswith("ambiguous locator")


@pytest.mark.parametrize(("variant", "exit_code"), [("same", 0), ("changed", 10)])
def test_cli_bind_and_replay(recorded, tmp_path, monkeypatch, capsys, variant, exit_code):
    import shutil

    import yaml

    from liftproof import cli

    journey, assets = recorded
    work = tmp_path / "work"
    jdir = work / "shop" / "journeys"
    j = copy.deepcopy(journey)
    j.save(jdir / "checkout.json")
    shutil.copytree(assets, jdir / "checkout" / "assets")
    arn = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:shop-login"
    monkeypatch.setattr(cli, "secret_value", lambda a, k: PASSWORD if a == arn else None)
    with ShopApp(variant) as target:
        project = tmp_path / "shop.yaml"
        project.write_text(yaml.safe_dump({"project": "shop", "web": {
            "source_url": "http://source.invalid", "target_url": target.url,
            "capture_bodies": ["/api/*"]}}))
        base = ["--project", str(project), "--workdir", str(work), "--format", "json"]
        # the password token is not bound yet: the journey is reported as not run
        assert cli.main(["replay", *base, "--run-id", "r-unbound"]) == 10
        [token] = j.secrets
        assert cli.main(["bind", *base, "--journey", "checkout", "--token", token,
                         "--secret-arn", arn]) == 0
        capsys.readouterr()
        assert cli.main(["validate", *base, "--run-id", "r-web"]) == exit_code
    out = json.loads(capsys.readouterr().out)
    report = json.loads((work / "shop" / "runs" / "r-web" / "report.json").read_text())
    unbound = json.loads((work / "shop" / "runs" / "r-unbound" / "report.json").read_text())
    assert unbound["journeys"][0]["status"] == "not_run"
    assert unbound["coverage"]["journeys_coverage_pct"] == 0.0
    assert report["mode"] == "validate" and out["counts"]["journeys"] == 1
    assert report["coverage"]["journeys_coverage_pct"] == 100.0
    assert report["coverage"]["journeys_success_pct"] == (100.0 if variant == "same" else 0.0)
    assert report["traceability"][0]["story"] == "ORD-14"
    assert report["timings"]["journeys"][0]["target_ms"] is not None
    assert PASSWORD not in (work / "shop" / "runs" / "r-web" / "report.html").read_text()


def test_parallel_journeys_opt_in(recorded):
    """Independent journeys at once: each keeps its own steps in order, results keep the
    journeys' order, and the result records that the run was parallel (spec 6)."""
    journey, assets = recorded
    journeys = []
    for i in range(4):
        j = copy.deepcopy(journey)
        j.journey_id = f"checkout-{i}"
        journeys.append(j)

    def run(workers):
        with ShopApp(latency_ms=100) as target:
            result = run_journeys(
                journeys,
                target_url=target.url,
                options=WebOptions(),
                emit=lambda _f: None,
                assets_dir=lambda j: assets,
                secret_values=lambda j: {t: PASSWORD for t in j.secrets},
                workers=workers,
            )
            return result, target.peak_sessions

    # whether the journeys overlapped, not how much faster they were: wall clock on a
    # small CI runner is mostly four browsers starting
    seq, seq_peak = run(1)
    par, par_peak = run(4)
    assert (seq.parallel, seq.workers) == (False, 1)
    assert (par.parallel, par.workers) == (True, 4)
    assert [j.journey for j in par.journeys] == [j.journey_id for j in journeys]
    assert {j.status for j in par.journeys} == {"passed"}
    assert (seq_peak, par_peak >= 2) == (1, True), (seq_peak, par_peak)


@pytest.mark.parametrize("value", [0, 9, "many"])
def test_parallel_journeys_is_bounded(tmp_path, value):
    from liftproof.config import load_project

    p = tmp_path / "p.yaml"
    p.write_text(f"project: t\nweb: {{source_url: http://a, parallel_journeys: {value}}}\n")
    with pytest.raises(ConfigError, match="parallel_journeys"):
        load_project(p)
