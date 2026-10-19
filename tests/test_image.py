"""What the AMI build installs (infra/packer). No image is built here; these checks run
the pieces that can run on any host and pin the rest."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

from liftproof import cli
from liftproof.errors import EXIT_DIFFERENCES
from liftproof.findings import Severity

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "infra/packer/files"


def _text(name: str) -> str:
    return (FILES / name).read_text(encoding="utf-8")


def test_cloudwatch_agent_finds_the_log_group_in_either_template(tmp_path):
    """Terraform's yamlencode quotes the keys; CloudFormation writes them bare."""
    code = re.search(r"python -c '\n(.*?)'\)", _text("mvt-cwagent-config"), re.S).group(1)
    code = code.replace("/etc/mvt/config.yaml", str(tmp_path / "config.yaml"))
    for written in ('"deployment": "x"\n"log_group": "/liftproof/x"\n',
                    "deployment: x\nlog_group: /liftproof/x\n"):  # fmt: skip
        (tmp_path / "config.yaml").write_text(written)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        assert out.stdout.strip() == "/liftproof/x"


def test_cloudwatch_agent_can_read_the_product_log():
    provision = _text("provision.sh")
    assert "usermod -aG adm cwagent" in provision
    assert "install -d -o mvt -g adm -m 2750 /var/log/mvt" in provision
    assert '"run_as_user": "cwagent"' in _text("mvt-cwagent-config")


def test_the_image_audits_what_it_installed():
    provision = _text("provision.sh")
    assert "pip-audit --strict" in provision and "-r /var/tmp/ami-requirements.txt" in provision
    packer = (ROOT / "infra/packer/liftproof.pkr.hcl").read_text(encoding="utf-8")
    download = packer.index('source      = "/var/tmp/ami-dependency-audit.txt"')
    assert packer.index("files/harden.sh") < download < packer.index("files/cleanup.sh")


def test_the_worked_example_finds_its_one_changed_amount(tmp_path, monkeypatch, capsys):
    """Spec 17: something runs on a fresh instance with nothing set up."""
    project = tmp_path / "example.yaml"
    project.write_text(_text("example/example.yaml").replace("/opt/mvt/example",
                                                            str(FILES / "example")))  # fmt: skip
    monkeypatch.setattr(cli, "INSTANCE_CONFIG", tmp_path / "no-instance-settings.yaml")
    code = cli.main(["files", "--project", str(project), "--workdir", str(tmp_path / "w"),
                     "--format", "json"])  # fmt: skip
    assert code == EXIT_DIFFERENCES
    report = json.loads(next((tmp_path / "w").rglob("report.json")).read_text())
    found = {(f["object"], f["severity"], f["locator"]) for f in report["findings"]}
    assert found == {
        ("invoices:2026-09.csv", Severity.HIGH, "row 3, amount"),
        ("exports:stock.csv", Severity.LOW, None),
    }
    assert yaml.safe_load(_text("example/example.yaml"))["project"] == "example"
    assert "/tmp/liftproof-files/example/example.yaml /var/lib/mvt/projects/" in _text(
        "provision.sh"
    )
    capsys.readouterr()


def test_a_replacement_instance_restores_its_projects_before_anything_runs():
    """Spec 3: the project files come back from S3 at first boot, before the scheduler
    or the UI looks for them, once per instance."""
    unit = _text("mvt-restore.service")
    assert "Before=mvt-scheduler.service mvt-ui.service" in unit
    assert "ConditionPathExists=!/var/lib/mvt/.restored" in unit
    assert "ExecStartPost=/usr/bin/touch /var/lib/mvt/.restored" in unit
    assert "liftproof restore --projects-dir /var/lib/mvt/projects" in unit
    assert "User=mvt" in unit and "Type=oneshot" in unit
    install = _text("scheduler.sh")
    assert "mvt-restore.service /etc/systemd/system/" in install
    assert "systemctl enable mvt-restore.service" in install


def test_the_marketplace_scan_can_reach_a_key_only_sshd():
    """Decision 135: the scan logs in over SSH; nobody else can, and never by password."""
    harden = _text("harden.sh")
    assert "systemctl mask ssh" not in harden
    for line in ("PasswordAuthentication no", "KbdInteractiveAuthentication no",
                 "PermitEmptyPasswords no", "PermitRootLogin no"):  # fmt: skip
        assert line in harden
    assert "/etc/ssh/sshd_config.d/10-liftproof.conf" in harden
    assert "find /home /root -name authorized_keys -delete" in _text("cleanup.sh")
    cfn = (ROOT / "infra/cloudformation/liftproof.yaml").read_text(encoding="utf-8")
    module = "".join(p.read_text(encoding="utf-8")
                     for p in (ROOT / "infra/modules/liftproof").glob("*.tf"))  # fmt: skip
    # the only inbound rule in either is HTTPS to the endpoints, never to the instance
    assert "KeyName" not in cfn and cfn.count("SecurityGroupIngress") == 1
    assert "key_name" not in module
    assert module.count('resource "aws_vpc_security_group_ingress_rule"') == 1
    assert 'resource "aws_vpc_security_group_ingress_rule" "endpoints"' in module


def test_the_source_ami_is_built_in_us_east_1():
    """Decision 134: AWS Marketplace takes a new AMI version only from us-east-1."""
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "AWS_REGION: us-east-1" in release
    packer = (ROOT / "infra/packer/liftproof.pkr.hcl").read_text(encoding="utf-8")
    assert re.search(r'variable "region" \{[^}]*default = "us-east-1"', packer)
    assert '"AWS_REGION=${var.region}"' in packer
    assert "${AWS_REGION}" in _text("provision.sh") and "ap-south-1" not in _text("provision.sh")
