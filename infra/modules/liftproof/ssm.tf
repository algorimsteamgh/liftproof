# How a pipeline starts a run without any inbound path to the instance (ATS-005).
# The run executes in its own systemd unit, so it survives an agent restart, and the
# document still returns the product's exit code: 0 clean, 10 differences, 2 run
# failed (including "another run of this project is in progress"), 3 configuration error.

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
        allowedValues = ["validate", "reconcile", "files", "replay", "smoke", "baseline", "rebaseline", "doctor", "support-bundle", "ui-login"]
      }
      journeys = {
        type           = "String"
        description    = "Comma separated journey ids for replay, smoke and validate; empty: all"
        default        = ""
        allowedPattern = "^([a-z0-9][a-z0-9-]{0,63}(,[a-z0-9][a-z0-9-]{0,63})*)?$"
      }
      sets = {
        type           = "String"
        description    = "Comma separated file set names for files and validate; empty: all"
        default        = ""
        allowedPattern = "^([A-Za-z0-9][A-Za-z0-9_-]{0,63}(,[A-Za-z0-9][A-Za-z0-9_-]{0,63})*)?$"
      }
      baseline = {
        type           = "String"
        description    = "Reference for reconcile and validate: latest (source), latest-target (after rebaseline) or a baseline id"
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
          "case '{{ mode }}' in reconcile|validate) args+=(--baseline {{ baseline }});; esac",
          "case '{{ mode }}' in replay|smoke|validate) [ -z '{{ journeys }}' ] || args+=(--journeys '{{ journeys }}');; esac",
          "case '{{ mode }}' in files|validate) [ -z '{{ sets }}' ] || args+=(--sets '{{ sets }}');; esac",
          "case '{{ mode }}' in ui-login) args=(--workdir /var/lib/mvt/projects --format json);; esac",
          "systemd-run --unit=liftproof-{{ project }}-$(date +%s) --wait --pipe --collect --quiet -p User=mvt -E LIFTPROOF_INVOKED_BY=ssm-run-command /opt/mvt/bin/liftproof {{ mode }} \"$${args[@]}\"",
        ]
      }
    }]
  })
}
