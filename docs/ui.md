# The web UI (Technical Spec 4)

A convenience over the CLI: see projects, runs and schedules, open reports, start runs,
and finish recorded journeys (bind secrets, confirm correlations). Everything it does it
does by running the same `liftproof` commands a pipeline or a schedule runs, so anything
you can do here you can also do from the CLI.

The UI runs on the Liftproof instance as the `mvt-ui` service, listening on port 8080 of
127.0.0.1 only. Nothing reaches it from the network; you reach it through Session Manager
port forwarding, with the operator policy the deployment creates (`operator_policy_arn`).

## Open it

1. Forward the port (the deployment's `connect_ui` output, `ConnectUi` in CloudFormation,
   prints this with a lookup of the instance in the deployment's Auto Scaling group, which
   replaces a failed instance, so its ID can change):

   ```sh
   aws ssm start-session --target i-0123456789abcdef0 \
     --document-name AWS-StartPortForwardingSession \
     --parameters portNumber=8080,localPortNumber=8080
   ```

2. Get a login link. It works once, within ten minutes:

   ```sh
   aws ssm send-command --instance-ids i-0123456789abcdef0 \
     --document-name Algorims-MVT-Run-<name> \
     --parameters project=any,mode=ui-login
   aws ssm get-command-invocation --instance-id i-0123456789abcdef0 --command-id <id> \
     --query StandardOutputContent --output text
   ```

   (On the instance itself: `sudo -u mvt liftproof ui-login`.) The `project` parameter
   is required by the document but not used for `ui-login`.

3. Open the `login_url` in your browser while the port forwarding session runs. The
   session lasts 12 hours; after that, get a new link.

Put your name in the box at the top. Runs you start are recorded in the report as
`ui:<your name>`. The UI takes your word for it: port forwarding carries no identity, so
this is a label, not proof of who you are.

## What it does not do

- **Recording.** `liftproof record` opens a browser window for you to click through the
  journey, so it runs on a machine with a display that can reach the source application
  and the project's store. The journey then shows up in the UI, where you can bind its
  secrets and confirm its correlations.
- **Showing values.** `--show-values` turns the report into a copy of your data; the UI
  never sets it. Use the CLI when you mean to.
- **Custom report templates.** Also CLI only (`--template`).
