"""S3 writes carry the encryption, retention and classification the bucket expects, and
the bucket, not an instance's copy, is what a journey and the content it kept are."""

import os

import pytest
from botocore.stub import ANY, Stubber

from liftproof import aws, cli
from liftproof.findings import Kind
from liftproof.store import LocalStore, S3Store
from liftproof.web.browser import Captured
from liftproof.web.compare import WebOptions, compare_journey
from liftproof.web.journey import Exchange, Journey, Step
from liftproof.web.replay import JourneyRun, StepRun

KEY = "arn:aws:kms:ap-south-1:111122223333:key/k"


def _store(**kw):
    client = aws.client("s3", region="ap-south-1")
    return S3Store("bucket", "acme", KEY, client, **kw)


def test_reports_are_locked_and_kms_encrypted(tmp_path):
    store = _store(report_lock_days=365)
    f = tmp_path / "report.html"
    f.write_text("x")
    with Stubber(store.s3) as stub:
        stub.add_response("put_object", {}, {
            "Bucket": "bucket", "Key": "acme/runs/r1/report.html", "Body": ANY,
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:ap-south-1:111122223333:key/k",
            "ObjectLockMode": "GOVERNANCE", "ObjectLockRetainUntilDate": ANY,
        })
        store.put_file("runs/r1/report.html", f)
        stub.assert_no_pending_responses()


def test_assets_are_tagged_for_expiry(tmp_path):
    store = _store()
    f = tmp_path / "body"
    f.write_text("x")
    with Stubber(store.s3) as stub:
        stub.add_response("put_object", {}, {
            "Bucket": "bucket", "Key": "acme/journeys/j1/assets/abc", "Body": ANY,
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:ap-south-1:111122223333:key/k",
            "Tagging": "liftproof:class=asset",
        })
        store.put_file("journeys/j1/assets/abc", f)
        stub.assert_no_pending_responses()


def test_kept_snapshots_reach_the_bucket_tagged_and_no_copy_stays(tmp_path):
    store = _store()
    step = Step(1, "goto", url="/orders/7", region_sha256="abc", region_asset="assets/abc")
    j = Journey("j1", "http://source.invalid", steps=[step])
    put = {"Bucket": "bucket", "Body": ANY, "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": KEY}
    with Stubber(store.s3) as stub:
        stub.add_response("put_object", {}, {**put, "Key": "acme/journeys/j1.json"})
        stub.add_response("put_object", {}, {**put, "Key": "acme/journeys/j1/assets/abc",
                                             "Tagging": "liftproof:class=asset"})  # fmt: skip
        cli._save_journey(store, tmp_path, j, {"abc": b'- heading "Order 7"'})
        stub.assert_no_pending_responses()
    assert (tmp_path / "journeys" / "j1.json").exists()
    assert not (tmp_path / "journeys" / "j1" / "assets" / "abc").exists()  # it expires (spec 5)


@pytest.fixture
def bucket():
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="ap-south-1")
        client.create_bucket(
            Bucket="bucket", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )
        yield S3Store("bucket", "acme", client=client)


def _recording(*urls):
    page = '- heading "Order 7"'
    steps = [Step(n, "goto", url=u, region_shape='- heading "*"', region_asset="assets/page",
                  exchanges=[Exchange("GET", "/api/orders/7", 200, body_asset="assets/body")])
             for n, u in enumerate(urls, 1)]  # fmt: skip
    return Journey("j1", "http://source.invalid", steps=steps, region_shape_version=1), {
        "page": page.encode(), "body": b'{"id": 7}'}


def test_the_bucket_holds_the_journey_and_what_it_kept(tmp_path, bucket):
    """A journey recorded again on another machine replaces this instance's copy (a bind
    here then saves that one), and content the bucket has expired goes from here too."""
    laptop, here = tmp_path / "laptop", tmp_path / "instance"
    cli._save_journey(bucket, laptop, *_recording("/orders/7"))
    first = cli._load_journey(bucket, here, "j1")
    cli._fetch_assets(bucket, here, [first])
    assets = here / "journeys" / "j1" / "assets"
    assert sorted(p.name for p in assets.iterdir()) == ["body", "page"]
    assert not list((laptop / "journeys" / "j1" / "assets").iterdir())
    copy = here / "journeys" / "j1.json"
    os.utime(copy, (copy.stat().st_mtime - 60,) * 2)  # copied a minute before the new one
    cli._save_journey(bucket, laptop, *_recording("/orders/7", "/orders"))
    again = cli._load_journey(bucket, here, "j1")
    assert [s.url for s in again.steps] == ["/orders/7", "/orders"]

    bucket.s3.delete_object(Bucket="bucket", Key="acme/journeys/j1/assets/page")  # expired
    cli._fetch_assets(bucket, here, [first])
    assert sorted(p.name for p in assets.iterdir()) == ["body"]
    got = Captured(Exchange("GET", "/api/orders/7", 200), 0.0, b'{"id": 7}', {"id": 7}, None)
    run = JourneyRun("j1", status="completed", attempts=1, steps=[
        StepRun(1, "goto", "ok", region='- heading "Order 9"', exchanges=[got])])  # fmt: skip
    findings = []
    cmp = compare_journey(first, run, WebOptions(), findings.append, assets)
    assert cmp.ui_compared == {"text": 0, "shape": 0, "expired": 1}
    assert [(f.kind, f.detail) for f in findings] == [
        (Kind.NOTICE, {"snapshots_expired": 1, "bodies_expired": 0})]


def test_what_the_bucket_expired_goes_from_every_journey_here(tmp_path, bucket):
    """Recording again leaves the old content in the bucket alone, to expire: then it goes
    from here too, as does that of a journey this replay leaves out."""
    laptop, here = tmp_path / "laptop", tmp_path / "instance"

    def record(jid, name):
        step = Step(1, "goto", url="/orders/7", region_shape='- heading "*"',
                    region_asset=f"assets/{name}")  # fmt: skip
        j = Journey(jid, "http://source.invalid", steps=[step], region_shape_version=1)
        cli._save_journey(bucket, laptop, j, {name: f'- heading "{name}"'.encode()})

    record("j1", "old")
    record("j2", "other")
    cli._fetch_assets(bucket, here, [cli._load_journey(bucket, here, j) for j in ("j1", "j2")])
    copy = here / "journeys" / "j1.json"
    os.utime(copy, (copy.stat().st_mtime - 60,) * 2)
    record("j1", "new")
    for key in ("j1/assets/old", "j2/assets/other"):  # expired
        bucket.s3.delete_object(Bucket="bucket", Key=f"acme/journeys/{key}")
    cli._fetch_assets(bucket, here, [cli._load_journey(bucket, here, "j1")])
    assert [p.name for p in (here / "journeys" / "j1" / "assets").iterdir()] == ["new"]
    assert not list((here / "journeys" / "j2" / "assets").iterdir())


def test_a_journey_only_this_instance_holds_keeps_what_it_kept(tmp_path, bucket):
    """Recorded before the project had a bucket: the bucket never held its content, so a
    replay neither deletes it nor compares that page as expired."""
    here = tmp_path / "instance"
    cli._save_journey(LocalStore(here), here, *_recording("/orders/7"))
    journey = cli._load_journey(bucket, here, "j1")
    cli._fetch_assets(bucket, here, [journey])
    assets = here / "journeys" / "j1" / "assets"
    assert sorted(p.name for p in assets.iterdir()) == ["body", "page"]
    run = JourneyRun("j1", status="completed", attempts=1,
                     steps=[StepRun(1, "goto", "ok", region='- heading "Order 7"')])
    cmp = compare_journey(journey, run, WebOptions(), lambda f: None, assets)
    assert cmp.ui_compared == {"text": 1, "shape": 0, "expired": 0}
