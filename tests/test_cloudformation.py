"""The CloudFormation template (AWS Marketplace) and the Terraform module deploy the same
thing. These checks catch one being changed without the other: the Run Command
document, the IAM statements, the instance settings, the endpoints and the inputs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CFN = ROOT / "infra/cloudformation/liftproof.yaml"
MODULE = ROOT / "infra/modules/liftproof"

# Terraform variable -> CloudFormation parameter(s). Every variable must be listed.
INPUTS = {
    "name": ["DeploymentName"],
    "ami_id": ["ImageId"],
    "instance_type": ["InstanceType"],
    "root_volume_gib": ["RootVolumeGiB"],
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


def test_customer_key_statements_are_published(template):
    """With the customer's own key the log group fails to create until its policy allows
    CloudWatch Logs; the statements are an output and in the deployment guide."""
    assert 'output "customer_key_policy_statements"' in tf("outputs.tf")
    guide = (ROOT / "infra/README.md").read_text(encoding="utf-8")
    for sid in re.findall(r'sid\s*=\s*"(\w+)"', tf("kms.tf")):
        if sid != "AccountAdministration":
            assert f'"Sid": "{sid}"' in guide, sid
    assert "Bring your own KMS key" in template["Parameters"]["KmsKeyArn"]["Description"]
