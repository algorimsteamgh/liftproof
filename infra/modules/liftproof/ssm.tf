# How a pipeline starts a run without any inbound path to the instance (ATS-005).
# The run executes in its own systemd unit, so it survives an agent restart, and the
# document still returns the product's exit code: 0 clean, 10 differences, 2 run
# failed, 3 configuration error.

resource "aws_ssm_document" "run" {
  name            = "Algorims-MVT-Run-${var.name}"
  document_type   = "Command"
  document_format = "YAML"
  target_type     = "/AWS::EC2::Instance"
  tags            = local.tags

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "Run a Liftproof validation and return its exit code"
    parameters = {
      project = {
        type           = "String"
        description    = "Project name (the project file under /var/lib/mvt/projects)"
        allowedPattern = "^[a-z0-9][a-z0-9-]{0,39}$"
      }
      mode = {
        type          = "String"
        default       = "reconcile"
        allowedValues = ["reconcile", "baseline", "validate", "smoke", "doctor"]
      }
      baseline = {
        type           = "String"
        default        = "latest"
        allowedPattern = "^(latest|b-[0-9]{8}-[0-9]{6}|[a-z0-9-]{1,40})$"
      }
      failOn = {
        type          = "String"
        default       = "differences"
        allowedValues = ["differences", "errors", "never"]
      }
      executionTimeout = {
        type           = "String"
        default        = "14400"
        allowedPattern = "^[0-9]{1,6}$"
      }
    }
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "liftproof"
      inputs = {
        timeoutSeconds = "{{ executionTimeout }}"
        runCommand = [
          "set -o pipefail",
          "args=(--project /var/lib/mvt/projects/{{ project }}.yaml --fail-on {{ failOn }} --format json)",
          "if [ '{{ mode }}' = reconcile ]; then args+=(--baseline {{ baseline }}); fi",
          "export LIFTPROOF_INVOKED_BY=\"ssm-run-command\"",
          "systemd-run --unit=liftproof-{{ project }}-$(date +%s) --wait --pipe --collect --quiet -p User=mvt /opt/mvt/bin/liftproof {{ mode }} \"$${args[@]}\"",
        ]
      }
    }]
  })
}
