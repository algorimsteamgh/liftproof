"""File comparison (PRD F7, Technical Spec 10).

PRD F7 done when: a generated invoice file that differs between source and target is
reported with both hashes. Spec 10: a regenerated document whose bytes differ but whose
text is identical ranks below a real difference.
"""

from __future__ import annotations

import hashlib
import json

import pytest
import yaml

from liftproof import cli
from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.files.compare import FileSetConfig, IgnoreFile, compare_files
from liftproof.files.sources import LocalSource, S3Source, open_source
from liftproof.files.text import extract
from liftproof.findings import Kind, Severity


def make_pdf(lines: list[str], created: str, doc_id: str) -> bytes:
    """A minimal valid PDF: one page of text, a creation date and a document id, the two
    things a regenerated document always changes."""
    content = "BT /F1 12 Tf 72 720 Td 14 TL " + " ".join(
        f"({t}) Tj T*" for t in lines
    ) + " ET"  # fmt: skip
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Producer (Liftproof test) /CreationDate (D:{created}) >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R "
        f"/ID [<{doc_id}> <{doc_id}>] >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode()
    return bytes(out)


INVOICE = ["INVOICE 2026-0042", "Acme Traders", "Total due: 1,250.00 INR"]
CSV_ROWS = "id,customer,amount\n1,Acme,10.50\n2,Globex,99.00\n"


def write(root, files: dict[str, bytes | str]) -> None:
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)


@pytest.fixture
def trees(tmp_path):
    src, tgt = tmp_path / "src", tmp_path / "tgt"
    write(src, {
        "same/logo.png": bytes(range(256)),
        "invoices/inv-41.pdf": make_pdf(INVOICE, "20260101090000Z", "a1" * 16),
        "invoices/inv-42.pdf": make_pdf(INVOICE, "20260101090000Z", "b2" * 16),
        "exports/orders.csv": CSV_ROWS.replace("\n", "\r\n"),
        "exports/totals.csv": CSV_ROWS,
        "exports/state.json": '{"b": 1, "a": [1, 2]}',
        "exports/legacy.txt": "Café crème\n".encode("cp1252"),
        "exports/printed.txt": "Daily report\nPrinted on 2026-01-01 09:00\nRows: 3\n",
        "blobs/archive.bin": b"\x00\x01\x02",
        "only/source.txt": "gone",
        "tmp/scratch.txt": "temporary",
    })  # fmt: skip
    write(tgt, {
        "same/logo.png": bytes(range(256)),
        # regenerated on the target: new date and id, same words
        "invoices/inv-41.pdf": make_pdf(INVOICE, "20261006120000Z", "c3" * 16),
        # regenerated with a different amount: the F7 acceptance case
        "invoices/inv-42.pdf": make_pdf(
            INVOICE[:2] + ["Total due: 1,205.00 INR"], "20261006120000Z", "d4" * 16
        ),
        "exports/orders.csv": CSV_ROWS,
        "exports/totals.csv": CSV_ROWS.replace("99.00", "99.0"),
        "exports/state.json": '{\n  "a": [1, 2],\n  "b": 1\n}\n',
        "exports/legacy.txt": "Café crème\n",
        "exports/printed.txt": "Daily report\nPrinted on 2026-10-06 12:00\nRows: 3\n",
        "blobs/archive.bin": b"\x00\x01\x03",
        "only/target.txt": "new",
    })  # fmt: skip
    return src, tgt


def _compare(src, tgt, **kw):
    c = FileSetConfig("docs", str(src), str(tgt), **kw)
    found = []
    result = compare_files([c], found.append, lambda c, w: open_source(getattr(c, w)))
    return result.sets[0], {f.object.split(":", 1)[1]: f for f in found}, found


def test_pdf_with_a_changed_amount_is_reported_with_both_hashes(trees):
    src, tgt = trees
    _, by_path, _ = _compare(src, tgt)
    f = by_path["invoices/inv-42.pdf"]
    assert (f.kind, f.severity) == (Kind.DIFFERENCE, Severity.HIGH)
    assert f.locator == "page 1, line 3"
    a = hashlib.sha256((src / "invoices/inv-42.pdf").read_bytes()).hexdigest()
    b = hashlib.sha256((tgt / "invoices/inv-42.pdf").read_bytes()).hexdigest()
    assert (f.detail["source_sha256"], f.detail["target_sha256"]) == (a, b)
    # content stays out of the report unless the file set opts in
    assert "1,205" not in json.dumps(f.to_dict())
    assert f.expected == f"sha256:{a[:12]}"


def test_regenerated_pdf_with_the_same_text_ranks_low(trees):
    src, tgt = trees
    _, by_path, _ = _compare(src, tgt)
    f = by_path["invoices/inv-41.pdf"]
    assert (f.kind, f.severity) == (Kind.DIFFERENCE, Severity.LOW)
    assert "text is identical" in f.summary and "PDF internals" in f.summary


def test_text_files_explain_why_bytes_differ(trees):
    src, tgt = trees
    _, by_path, _ = _compare(src, tgt)
    assert "line endings crlf became lf" in by_path["exports/orders.csv"].summary
    assert "cp1252 became utf-8" in by_path["exports/legacy.txt"].summary
    assert "JSON formatting" in by_path["exports/state.json"].summary
    for p in ("exports/orders.csv", "exports/legacy.txt", "exports/state.json"):
        assert by_path[p].severity == Severity.LOW


def test_csv_difference_names_the_row_and_column(trees):
    src, tgt = trees
    _, by_path, _ = _compare(src, tgt, show_content=True)
    f = by_path["exports/totals.csv"]
    assert f.severity == Severity.HIGH
    assert (f.locator, f.column, f.expected, f.actual) == (
        "row 3, amount",
        "amount",
        "99.00",
        "99.0",
    )


def test_masks_hide_volatile_text(trees):
    src, tgt = trees
    _, by_path, _ = _compare(src, tgt)
    assert by_path["exports/printed.txt"].severity == Severity.HIGH
    assert by_path["exports/printed.txt"].locator == "line 2"
    _, by_path, _ = _compare(src, tgt, ignore_text=[r"Printed on [0-9: -]+"])
    f = by_path["exports/printed.txt"]
    assert f.severity == Severity.LOW and "masked text" in f.summary


def test_missing_extra_binary_and_ignored(trees):
    src, tgt = trees
    res, by_path, found = _compare(
        src, tgt, ignore=[IgnoreFile("tmp/*", "scratch files are not migrated")]
    )
    assert by_path["only/source.txt"].summary == "file missing in target"
    assert by_path["only/source.txt"].severity == Severity.HIGH
    assert by_path["only/target.txt"].summary == "file only in target"
    assert by_path["blobs/archive.bin"].summary == "file content differs"
    assert by_path["tmp/scratch.txt"].kind == Kind.NOTICE
    assert "same/logo.png" not in by_path
    assert (res.files, res.matched, res.missing, res.extra, res.excluded) == (10, 1, 1, 1, 1)
    assert (res.different, res.text_equal) == (8, 4)


def test_include_path_map_and_case(tmp_path):
    src, tgt = tmp_path / "s", tmp_path / "t"
    write(src, {"Archive/A.TXT": "x", "Archive/b.log": "y", "skip.bin": b"z"})
    write(tgt, {"old/a.txt": "x", "old/b.log": "y"})
    res, by_path, _ = _compare(
        src, tgt, include=["*.TXT", "*.txt", "*.log"], path_map=[("^Archive/", "old/")],
        case_insensitive=True,
    )  # fmt: skip
    assert by_path == {}
    assert (res.files, res.matched) == (2, 2)


def test_unreadable_file_is_not_checked(tmp_path, monkeypatch):
    src, tgt = tmp_path / "s", tmp_path / "t"
    write(src, {"a.txt": "x"})
    write(tgt, {"a.txt": "x"})
    real = LocalSource.open

    def denied(self, path):
        if self.root == src:
            raise PermissionError(13, "Permission denied")
        return real(self, path)

    monkeypatch.setattr(LocalSource, "open", denied)
    res, by_path, _ = _compare(src, tgt)
    assert by_path["a.txt"].kind == Kind.NOT_CHECKED and res.not_checked == 1
    assert "cannot read the source file" in by_path["a.txt"].summary


def test_symlinks_are_not_followed(tmp_path):
    src, tgt = tmp_path / "s", tmp_path / "t"
    write(src, {"a.txt": "x"})
    write(tgt, {"a.txt": "x"})
    (src / "link.txt").symlink_to("/etc/hostname")
    res, by_path, _ = _compare(src, tgt)
    assert by_path["link.txt"].kind == Kind.NOT_CHECKED
    assert "symbolic link" in by_path["link.txt"].summary


def test_extract_understands_types():
    assert extract("x.bin", b"\x00") is None
    t = extract("a.json", b'{"z": 1, "a": {"c": 2, "b": 3}}')
    assert t.kind == "json" and t.lines[0] == "{"
    assert extract("a.json", b"not json").kind == "text"
    assert extract("a.tsv", b"a\tb\n1\t2\n").header == ["a", "b"]


@pytest.fixture
def s3():
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="ap-south-1")
        client.create_bucket(
            Bucket="acme-docs", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )
        yield client


def test_local_source_against_s3_target(trees, s3, monkeypatch):
    src, tgt = trees
    for p in sorted(tgt.rglob("*")):
        if p.is_file():
            s3.put_object(Bucket="acme-docs", Key=f"invoices/{p.relative_to(tgt).as_posix()}",
                          Body=p.read_bytes())  # fmt: skip
    s3.put_object(Bucket="acme-docs", Key="invoices/folder/", Body=b"")
    s3_side = S3Source("acme-docs", "invoices", client=s3)
    assert s3_side.describe() == "s3://acme-docs/invoices/"
    local_res, local_found, _ = _compare(src, tgt)
    c = FileSetConfig("docs", str(src), "s3://acme-docs/invoices")
    found = []
    res = compare_files(
        [c], found.append, lambda c, w: LocalSource(str(src)) if w == "source" else s3_side
    ).sets[0]
    assert {f.object for f in found} == {f"docs:{p}" for p in local_found}
    assert (res.matched, res.different, res.missing, res.extra) == (
        local_res.matched, local_res.different, local_res.missing, local_res.extra,
    )  # fmt: skip


def test_config_rules(tmp_path):
    f = tmp_path / "p.yaml"

    def load(files):
        f.write_text(yaml.safe_dump({"project": "p", "files": files}))
        return load_project(f)

    p = load([{"name": "inv", "source": "/a", "target": {"location": "s3://b/p",
              "endpoint_url": "https://minio.internal", "secret_arn": "arn:x"}}])  # fmt: skip
    [c] = p.files
    assert (c.target, c.target_endpoint_url, c.target_secret_arn) == (
        "s3://b/p", "https://minio.internal", "arn:x",
    )  # fmt: skip
    with pytest.raises(ConfigError, match="reason"):
        load([{"name": "a", "source": "/a", "target": "/b", "ignore": [{"path": "x"}]}])
    with pytest.raises(ConfigError, match="used twice"):
        load([{"name": "a", "source": "/a", "target": "/b"}] * 2)
    with pytest.raises(ConfigError, match="regular expression"):
        load([{"name": "a", "source": "/a", "target": "/b", "ignore_text": ["("]}])
    with pytest.raises(ConfigError, match="only local paths"):
        open_source("ftp://x/y")


def test_cli_files_run(trees, tmp_path, capsys):
    src, tgt = trees
    project = tmp_path / "docs.yaml"
    project.write_text(yaml.safe_dump({"project": "docs", "files": [
        {"name": "documents", "source": str(src), "target": str(tgt),
         "ignore": [{"path": "tmp/*", "reason": "scratch files"}]}]}))  # fmt: skip
    work = tmp_path / "work"
    base = ["--project", str(project), "--workdir", str(work), "--format", "json"]
    assert cli.main(["files", *base, "--run-id", "r-files"]) == 10
    out = json.loads(capsys.readouterr().out)
    assert out["counts"]["files"] == 10 and out["counts"]["files_missing"] == 1
    run = work / "docs" / "runs" / "r-files"
    report = json.loads((run / "report.json").read_text())
    assert report["mode"] == "files" and report["verdict"] == "failed"
    assert report["coverage"]["files_coverage_pct"] == 100.0
    assert report["coverage"]["files_success_pct"] == 10.0
    assert report["file_sets"][0]["text_equal"] == 4
    assert {"object": "documents:tmp/scratch.txt", "column": None,
            "reason": "scratch files"} in report["coverage"]["exclusions"]  # fmt: skip
    html = (run / "report.html").read_text()
    assert "<h2>Files</h2>" in html and "tables in scope" not in html
    # the report regenerates from the saved results
    assert cli.main(["report", *base, "--run", "r-files"]) == 10
    assert cli.main(["doctor", *base]) == 0
