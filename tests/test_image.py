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


def _cwagent_config(tmp_path, written: str) -> dict | None:
    code = re.search(r"python -c '\n(.*?)' >", _text("mvt-cwagent-config"), re.S).group(1)
    code = code.replace("/etc/mvt/config.yaml", str(tmp_path / "config.yaml"))
    (tmp_path / "config.yaml").write_text(written)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout) if out.stdout.strip() else None


def test_cloudwatch_agent_finds_the_log_group_in_either_template(tmp_path):
    """Terraform's yamlencode quotes the keys; CloudFormation writes them bare."""
    for written in ('"deployment": "x"\n"log_group": "/liftproof/x"\n',
                    "deployment: x\nlog_group: /liftproof/x\n"):  # fmt: skip
        config = _cwagent_config(tmp_path, written)
        [files] = config["logs"]["logs_collected"]["files"]["collect_list"]
        assert files["log_group_name"] == "/liftproof/x"
    assert _cwagent_config(tmp_path, "region: ap-south-1\n") is None  # not a deployment


def test_cloudwatch_agent_publishes_what_the_alarms_watch(tmp_path):
    """Root volume and memory use go to the one namespace the instance role may publish
    to, with the Deployment dimension the templates' root volume alarm names."""
    config = _cwagent_config(tmp_path, "deployment: x\nlog_group: /liftproof/x\n")
    metrics = config["metrics"]
    assert metrics["namespace"] == "Liftproof"
    disk, mem = metrics["metrics_collected"]["disk"], metrics["metrics_collected"]["mem"]
    assert disk["resources"] == ["/"] and disk["measurement"] == ["used_percent"]
    assert disk["drop_device"] is True  # leaves path and fstype, which the alarm names
    assert disk["append_dimensions"] == mem["append_dimensions"] == {"Deployment": "x"}
    assert mem["measurement"] == ["mem_used_percent"]
    assert config["agent"]["omit_hostname"] is True
    iam = (ROOT / "infra/modules/liftproof/iam.tf").read_text(encoding="utf-8")
    assert 'values   = ["Liftproof"]' in iam  # the PutMetricData condition


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


def test_the_image_does_not_patch_itself():
    """Patches arrive as new Marketplace versions (decision 138): the instance has no
    route to the archive, and the image must stay the one the release scan passed."""
    harden = _text("harden.sh")
    assert 'APT::Periodic::Unattended-Upgrade "0";' in harden
    assert "systemctl disable apt-daily.timer apt-daily-upgrade.timer" in harden
    assert "/etc/mvt/image-built" in harden
    assert "dist-upgrade" in _text("provision.sh")
    assert "## Patching" in (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_files_folder_exists_before_its_contents_are_uploaded():
    """A file provisioner whose source ends in "/" copies into an existing folder; the
    first release build failed with scp "Not a directory" without the mkdir before it."""
    hcl = (ROOT / "infra/packer/liftproof.pkr.hcl").read_text(encoding="utf-8")
    assert hcl.index("mkdir -p /tmp/liftproof-files") < hcl.index(
        'source      = "${path.root}/files/"'
    )


def test_builder_reaches_the_ubuntu_archive():
    """The image build runs apt against the Ubuntu archive, which is plain HTTP; the
    builder's security group allowed only 443 and apt-get update timed out (v0.1.0rc2)."""
    tf = (ROOT / "infra/modules/build-account/main.tf").read_text(encoding="utf-8")
    rule = tf.split('resource "aws_vpc_security_group_egress_rule" "builder_http"')[1]
    assert "from_port         = 80" in rule.split("}")[0]


def test_provisioner_scripts_receive_their_environment():
    """A custom execute_command must place {{ .Vars }} itself, or environment_vars never
    reach the script: v0.1.0rc2 stopped at "AWS_REGION: unbound variable"."""
    hcl = (ROOT / "infra/packer/liftproof.pkr.hcl").read_text(encoding="utf-8")
    commands = re.findall(r'execute_command\s*=\s*"([^"]*)"', hcl)
    assert commands and all("{{ .Vars }}" in c for c in commands), commands


def test_playwright_driver_has_its_libraries():
    """Playwright's bundled Node driver links libatomic.so.1, which minimal Ubuntu bases
    leave out; without it `playwright install` fails before downloading anything."""
    assert re.search(r"apt-get -y install [^\n]*\blibatomic1\b", _text("provision.sh"))


def test_the_image_keeps_only_the_newest_kernel():
    """The builder runs the base image's kernel while dist-upgrade installs a newer one,
    and autoremove keeps the running kernel; its packages would fail the Inspector gate."""
    cleanup = _text("cleanup.sh")
    assert "apt-get -y purge $old" in cleanup
    assert cleanup.index("apt-get -y purge $old") < cleanup.index("apt-get -y autoremove")
    assert "DEBIAN_FRONTEND=noninteractive" in cleanup  # no prompt for the running kernel


def test_release_role_may_create_the_image():
    """CreateImage is authorized on the new image and snapshot too, which carry no build
    tag yet, so the tag-conditioned statement alone refuses it."""
    tf = (ROOT / "infra/modules/build-account/main.tf").read_text(encoding="utf-8")
    publish = tf.split('sid = "PublishImages"')[1].split("statement {")[0]
    assert '"ec2:CreateImage"' in publish and "image/*" in publish and "snapshot/*" in publish


def test_scan_waits_for_a_finished_scan():
    """Inspector coverage turns ACTIVE with reason PENDING_INITIAL_SCAN before anything
    is scanned; reading findings then would pass an unscanned image."""
    scan = (ROOT / "infra/scripts/scan-ami.sh").read_text(encoding="utf-8")
    assert "lastScannedAt" in scan and "PENDING_INITIAL_SCAN" in scan
    assert 'select(.fixAvailable != \\"NO\\")' in scan


def test_the_image_drops_the_venv_bootstrap_wheels():
    """Inspector flagged the pip and urllib3 copies in python3-pip-whl (v0.1.0rc3); they
    serve only `python -m venv`, which nothing on the instance runs after the build."""
    cleanup = _text("cleanup.sh")
    purge = "apt-get -y purge python3.12-venv python3-pip-whl python3-setuptools-whl"
    assert purge in cleanup and cleanup.index(purge) < cleanup.index("apt-get -y autoremove")
    assert cleanup.index("apt-mark manual python3.12") < cleanup.index(purge)
    import liftproof

    src = Path(liftproof.__file__).parent
    assert not any("ensurepip" in f.read_text(encoding="utf-8") or "-m venv" in f.read_text(
        encoding="utf-8") for f in src.rglob("*.py"))
