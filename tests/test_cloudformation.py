"""The CloudFormation template (AWS Marketplace) and the Terraform module deploy the same
thing. These checks catch one being changed without the other: the Run Command
document, the IAM statements, the instance settings, the endpoints and the inputs.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from liftproof import aws

ROOT = Path(__file__).resolve().parents[1]
CFN = ROOT / "infra/cloudformation/liftproof.yaml"
MODULE = ROOT / "infra/modules/liftproof"

# Terraform variable -> CloudFormation parameter(s). Every variable must be listed.
INPUTS = {
    "name": ["DeploymentName"],
    "ami_id": ["ImageId"],
    "instance_type": ["InstanceType"],
    "root_volume_gib": ["RootVolumeGiB"],
    "instance_generation": ["InstanceGeneration"],
    "vpc_id": ["VpcId"],
    "subnet_id": ["SubnetId"],
    "create_vpc_endpoints": ["CreateVpcEndpoints"],
    "endpoint_subnet_ids": ["EndpointSubnetIds"],
    "private_route_table_ids": ["PrivateRouteTableIds"],
    "database_egress": [f"Database{i}{p}" for i in range(1, 5) for p in ("Cidr", "Port")],
    "application_egress_cidrs": ["ApplicationCidrs"],
    "application_egress_ports": ["ApplicationPort"],
    "kms_key_arn": ["KmsKeyArn"],
    "secret_arns": ["SecretArns"],
    "secret_kms_key_arns": ["SecretKmsKeyArns"],
    "bucket_name": ["BucketName"],
    "report_lock_days": ["ReportLockDays"],
    "asset_retention_days": ["AssetRetentionDays"],
    "noncurrent_version_days": ["NoncurrentVersionDays"],
    "access_log_bucket": ["AccessLogBucket"],
    "log_retention_days": ["LogRetentionDays"],
    "operator_principal_arns": ["OperatorPrincipalArns"],
    "alarm_topic_arn": ["AlarmTopicArn"],
    "aws_requests_per_second": ["AwsRequestsPerSecond"],
    "tags": [],  # stack tags propagate in CloudFormation
}


@pytest.fixture(scope="module")
def template():
    return yaml.safe_load(CFN.read_text(encoding="utf-8"))


def tf(name: str) -> str:
    return (MODULE / name).read_text(encoding="utf-8")


def test_every_terraform_input_has_a_parameter(template):
    variables = re.findall(r'^variable "(\w+)"', tf("variables.tf"), re.M)
    assert sorted(variables) == sorted(INPUTS)
    params = set(template["Parameters"])
    mapped = {p for ps in INPUTS.values() for p in ps}
    assert mapped == params
    grouped = {
        p for g in template["Metadata"]["AWS::CloudFormation::Interface"]["ParameterGroups"]
        for p in g["Parameters"]
    }  # fmt: skip
    assert grouped == params  # every parameter appears in the console form


def test_run_document_is_the_same(template):
    content = template["Resources"]["RunDocument"]["Properties"]["Content"]
    ssm = tf("ssm.tf")
    block = ssm[ssm.index("runCommand = [") : ssm.index("]\n", ssm.index("runCommand = ["))]
    tf_lines = [
        json.loads(s).replace("$${", "${") for s in re.findall(r'^\s+(".*"),?$', block, re.M)
    ]
    [step] = content["mainSteps"]
    assert step["inputs"]["runCommand"] == tf_lines
    params_block = ssm[ssm.index("parameters = {") : ssm.index("mainSteps")]
    tf_params = re.findall(r"^      (\w+) = \{", params_block, re.M)
    assert sorted(content["parameters"]) == sorted(tf_params)
    modes = re.search(r"mode = \{.*?allowedValues = (\[.*?\])", ssm, re.S).group(1)
    assert content["parameters"]["mode"]["allowedValues"] == json.loads(modes)
    for name, p in content["parameters"].items():
        pattern = re.search(rf"{name} = \{{.*?allowedPattern = (\".*?\")\n", ssm, re.S)
        if "allowedPattern" in p:
            assert p["allowedPattern"] == json.loads(pattern.group(1)), name


def _sids(statements) -> set[str]:
    return {s["Sid"] for s in statements}


def test_iam_statements_match(template):
    iam = tf("iam.tf")
    instance_tf = iam[iam.index('data "aws_iam_policy_document" "instance"') : iam.index(
        'resource "aws_iam_role_policy" "instance"')]  # fmt: skip
    operator_tf = iam[iam.index('data "aws_iam_policy_document" "operator"') : iam.index(
        'resource "aws_iam_policy" "operator"')]  # fmt: skip
    r = template["Resources"]
    [runtime] = r["InstanceRole"]["Properties"]["Policies"]
    assert _sids(runtime["PolicyDocument"]["Statement"]) == set(
        re.findall(r'sid\s*=\s*"(\w+)"', instance_tf)
    )
    assert _sids(r["OperatorPolicy"]["Properties"]["PolicyDocument"]["Statement"]) == set(
        re.findall(r'sid\s*=\s*"(\w+)"', operator_tf)
    )
    for statement in runtime["PolicyDocument"]["Statement"]:
        actions = statement["Action"] if isinstance(statement["Action"], list) else [
            statement["Action"]]  # fmt: skip
        for action in actions:
            assert f'"{action}"' in instance_tf, action


def test_instance_settings_match(template):
    tf_keys = re.findall(
        r"^    (\w+)\s+=",
        tf("compute.tf").split("instance_config = yamlencode({")[1].split("})")[0],
        re.M,
    )
    user_data = template["Resources"]["Instance"]["Properties"]["UserData"]["Fn::Base64"]
    cfn_keys = re.findall(r"^\s+(\w+): \$\{", user_data["Fn::Sub"][0], re.M)
    assert sorted(cfn_keys) == sorted(tf_keys)
    # every product process runs as mvt, so the file must be readable by that group
    for user_data_text in (user_data["Fn::Sub"][0], tf("compute.tf")):
        written = re.search(
            r'path: /etc/mvt/config\.yaml\s+permissions: "(\d+)"\s+owner: (\S+)', user_data_text
        )
        assert written.groups() == ("0640", "root:mvt")
    lt = template["Resources"]["LaunchTemplate"]["Properties"]["LaunchTemplateData"]
    assert lt["MetadataOptions"]["HttpTokens"] == "required"
    assert lt["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True


def test_endpoints_match(template):
    names = re.search(r"toset\(\[(.*?)\]\)", tf("network.tf"), re.S).group(1)
    tf_endpoints = set(re.findall(r'"(\w+)"', names))
    cfn = {
        r["Properties"]["ServiceName"]["Fn::Sub"].rsplit(".", 1)[1]
        for r in template["Resources"].values()
        if r["Type"] == "AWS::EC2::VPCEndpoint"
        and r["Properties"]["VpcEndpointType"] == "Interface"
    }
    assert cfn == tf_endpoints
    gateways = {
        r["Properties"]["ServiceName"]["Fn::Sub"].rsplit(".", 1)[1]
        for r in template["Resources"].values()
        if r["Type"] == "AWS::EC2::VPCEndpoint" and r["Properties"]["VpcEndpointType"] == "Gateway"
    }
    # what doctor checks is what the deployment creates
    assert set(aws.GATEWAY_SERVICES) == gateways
    assert sorted(aws.ENDPOINT_SERVICES) == sorted(tf_endpoints | gateways)


def test_no_inbound_and_no_public_address(template):
    r = template["Resources"]
    assert "SecurityGroupIngress" not in r["InstanceSecurityGroup"]["Properties"]
    assert not [x for x in r.values() if x["Type"] == "AWS::EC2::SecurityGroupIngress"]
    [nic] = r["Instance"]["Properties"]["NetworkInterfaces"]
    assert nic["AssociatePublicIpAddress"] is False
    assert not [x for x in r.values() if x["Type"] in ("AWS::IAM::User", "AWS::IAM::AccessKey")]


def test_alarm_dimension_is_what_the_cli_publishes(template):
    """The skipped run alarm watches the Deployment dimension (cli._skipped)."""
    dims = template["Resources"]["SkippedRunsAlarm"]["Properties"]["Dimensions"]
    assert [d["Name"] for d in dims] == ["Deployment"]
    assert "dimensions          = { Deployment = var.name }" in tf("monitoring.tf")


def test_alarms_match(template):
    """The same alarms in both templates: metric, dimensions, threshold and action, and
    the product's metrics are the ones the CLI and the CloudWatch agent publish."""
    cfn = {}
    for res in template["Resources"].values():
        if res["Type"] != "AWS::CloudWatch::Alarm":
            continue
        p = res["Properties"]
        dims = {d["Name"]: d["Value"] if isinstance(d["Value"], str) else "<name>"
                for d in p["Dimensions"]}  # fmt: skip
        actions = json.dumps(p.get("AlarmActions"))
        action = next((a for a in ("recover", "reboot") if f"ec2:{a}" in actions), None)
        cfn[p["MetricName"]] = (p["Namespace"], dims, float(p["Threshold"]), action)
    tfm = {}
    for block in tf("monitoring.tf").split('resource "aws_cloudwatch_metric_alarm"')[1:]:
        metric = re.search(r'metric_name\s*=\s*"(\w+)"', block).group(1)
        namespace = re.search(r'namespace\s*=\s*"([\w/]+)"', block).group(1)
        raw = re.search(r"dimensions\s*=\s*\{(.*?)\}", block).group(1)
        dims = {}
        for k, v in re.findall(r'(\w+)\s*=\s*("[^"]*"|[\w.]+)', raw):
            dims[k] = v.strip('"') if v.startswith('"') else "<name>"
        threshold = float(re.search(r"threshold\s*=\s*(\d+)", block).group(1))
        action = next((a for a in ("recover", "reboot") if f"ec2:{a}" in block), None)
        tfm[metric] = (namespace, dims, threshold, action)
    assert cfn == tfm
    assert set(cfn) == {
        "StatusCheckFailed_System", "StatusCheckFailed_Instance", "ScheduledRunSkipped",
        "RunFailed", "disk_used_percent",
    }  # fmt: skip
    cli_src = (ROOT / "src/liftproof/cli.py").read_text(encoding="utf-8")
    assert '"RunFailed"' in cli_src and '"ScheduledRunSkipped"' in cli_src
    agent = (ROOT / "infra/packer/files/mvt-cwagent-config").read_text(encoding="utf-8")
    assert '"used_percent"' in agent and '"resources": ["/"]' in agent


def test_customer_key_statements_are_published(template):
    """With the customer's own key the log group fails to create until its policy allows
    CloudWatch Logs; the statements are an output and in the deployment guide."""
    assert 'output "customer_key_policy_statements"' in tf("outputs.tf")
    guide = (ROOT / "infra/README.md").read_text(encoding="utf-8")
    for sid in re.findall(r'sid\s*=\s*"(\w+)"', tf("kms.tf")):
        if sid != "AccountAdministration":
            assert f'"Sid": "{sid}"' in guide, sid
    assert "Bring your own KMS key" in template["Parameters"]["KmsKeyArn"]["Description"]


def test_raising_the_generation_replaces_the_instance(template):
    """A lost instance is replaced at the same image version in either template
    (decision 139): Terraform through replace_triggered_by, CloudFormation through a new
    launch template version, which an instance can only take by being replaced."""
    assert "replace_triggered_by = [terraform_data.instance_generation]" in tf("compute.tf")
    r = template["Resources"]
    [volume] = r["LaunchTemplate"]["Properties"]["LaunchTemplateData"]["TagSpecifications"]
    assert {"Key": "liftproof:generation", "Value": {"Ref": "InstanceGeneration"}} in volume["Tags"]
    version = r["Instance"]["Properties"]["LaunchTemplate"]["Version"]
    assert version == {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]}


def test_the_deployment_guide_names_every_alarm_and_input_it_relies_on(template):
    """The deployment guide is what a customer (and the Foundational Technical Review)
    reads: every alarm the templates create is in its alarm table, and the inputs it
    tells people to change exist in both templates."""
    guide = (ROOT / "docs/deployment-guide.md").read_text(encoding="utf-8")
    for res in template["Resources"].values():
        if res["Type"] == "AWS::CloudWatch::Alarm":
            suffix = res["Properties"]["AlarmName"]["Fn::Sub"].split("${DeploymentName}")[1]
            assert f"`liftproof-NAME{suffix}`" in guide
    for variable, params in INPUTS.items():
        if f"`{variable}`" in guide:
            assert all(f"`{p}`" in guide or f"**{p}**" in guide for p in params), variable
    for param in ("InstanceGeneration", "ImageId", "AlarmTopicArn"):
        assert param in template["Parameters"] and param in guide
    for heading in ("Prerequisites", "Costs", "Credentials", "Backup and recovery",
                    "Routine maintenance", "Troubleshooting and support"):  # fmt: skip
        assert re.search(rf"^## \d+\. {heading}", guide, re.M), heading
    assert (ROOT / "docs/architecture.png").stat().st_size > 0
    assert "architecture.svg" in guide


def _render_run_document(template, **params) -> str:
    content = template["Resources"]["RunDocument"]["Properties"]["Content"]
    values = {k: str(v.get("default", "")) for k, v in content["parameters"].items()}
    values.update(params)
    script = "\n".join(content["mainSteps"][0]["inputs"]["runCommand"])
    return re.sub(r"\{\{ (\w+) \}\}", lambda m: values[m.group(1)], script)


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash not installed")
@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (
            {"mode": "doctor"},
            "doctor --project /var/lib/mvt/projects/example.yaml --fail-on {failOn} --format json",
        ),
        (
            {"mode": "validate", "journeys": "login checkout", "sets": "docs"},
            "validate --project /var/lib/mvt/projects/example.yaml --fail-on {failOn} "
            "--format json --baseline {baseline} --journeys login|checkout --sets docs",
        ),
        (
            {"mode": "reconcile", "resume": "true"},
            "reconcile --project /var/lib/mvt/projects/example.yaml --fail-on {failOn} "
            "--format json --baseline {baseline} --resume",
        ),
        ({"mode": "ui-login"}, "ui-login --workdir /var/lib/mvt/projects --format json"),
    ],
)
def test_run_document_runs_under_sh(template, tmp_path, params, expected):
    """aws:runShellScript runs the commands with /bin/sh, which is dash on Ubuntu."""
    content = template["Resources"]["RunDocument"]["Properties"]["Content"]
    defaults = {k: str(v.get("default", "")) for k, v in content["parameters"].items()}
    params = {"project": "example", **params}
    stub = tmp_path / "systemd-run"
    # print liftproof's own arguments one per line, then exit with a known status
    stub.write_text('#!/bin/sh\nwhile [ "$1" != /opt/mvt/bin/liftproof ]; do shift; done\n'
                    'shift\nprintf "%s\\n" "$@"\nexit 3\n')  # fmt: skip
    stub.chmod(0o755)
    script = _render_run_document(template, **params)
    out = subprocess.run(
        ["dash", "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
    )
    assert out.stderr == ""
    assert out.returncode == 3  # liftproof's exit status reaches SSM unchanged
    want = expected.format(**defaults).split(" ")
    want = [w.replace("|", " ") for w in want]  # "|" marks a space inside one argument
    assert out.stdout.splitlines() == want
