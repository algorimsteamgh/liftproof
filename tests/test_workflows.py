"""The release gates in .github/workflows do what the PRD says they do. These failures
only show on a real release, so they are checked here on every build."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.yml"))


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_piped_steps_fail_when_the_first_command_fails(path):
    """ATS-009: `pip-audit | tee log` must fail the job. GitHub's implicit shell has no
    pipefail; `shell: bash` runs `bash -eo pipefail`."""
    workflow = _load(path)
    default = workflow.get("defaults", {}).get("run", {}).get("shell")
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "|" in step.get("run", ""):
                assert step.get("shell", job.get("defaults", {}).get("run", {}).get(
                    "shell", default)) == "bash", step  # fmt: skip


def test_release_job_presents_a_subject_the_role_trusts():
    """A job with `environment:` gets the OIDC subject repo:R:environment:E, which the
    release role (trusting only refs) refuses."""
    trust = (ROOT / "infra/modules/build-account/main.tf").read_text(encoding="utf-8")
    subjects = re.search(r'"repo:\$\{var\.github_repository\}:(\w+):', trust).group(1)
    assert subjects == "ref"
    for job in _load(ROOT / ".github/workflows/release.yml")["jobs"].values():
        uses = [s.get("uses", "") for s in job.get("steps", [])]
        if any(u.startswith("aws-actions/configure-aws-credentials") for u in uses):
            assert "environment" not in job


def test_blocked_release_keeps_its_audit_log():
    """The evidence step needs AWS credentials, so they come before the gate."""
    job = _load(ROOT / ".github/workflows/release.yml")["jobs"]["ami"]
    names = [s.get("uses", "") or s.get("name", "") for s in job["steps"]]
    credentials = next(i for i, n in enumerate(names) if "configure-aws-credentials" in n)
    gate = names.index("Dependency gate (ATS-009)")
    evidence = job["steps"][names.index("Keep evidence")]
    assert credentials < gate and evidence["if"] == "always()"
    assert "pip-audit.log" in evidence["run"]


def test_release_waits_for_the_suite_review_and_version():
    """OPE-004 and B6: the tagged commit passes the functional suite, sits on main, and
    the product it builds reports the tag's version."""
    assert "workflow_call" in _load(ROOT / ".github/workflows/ci.yml")[True]
    jobs = _load(ROOT / ".github/workflows/release.yml")["jobs"]
    assert jobs["tests"]["uses"] == "./.github/workflows/ci.yml"
    assert set(jobs["ami"]["needs"]) == {"performance", "tests", "reviewed"}
    checks = " ".join(s.get("run", "") for s in jobs["reviewed"]["steps"])
    assert "merge-base --is-ancestor" in checks and "__version__" in checks
