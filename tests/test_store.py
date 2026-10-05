"""S3 writes carry the encryption, retention and classification the bucket expects."""

from botocore.stub import ANY, Stubber

from liftproof import aws
from liftproof.store import S3Store


def _store(**kw):
    client = aws.client("s3", region="ap-south-1")
    return S3Store("bucket", "acme", "arn:aws:kms:ap-south-1:111122223333:key/k", client, **kw)


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
