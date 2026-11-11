# Security

Report a vulnerability in Liftproof to security@algorims.com. Security issues are tracked
in the security queue of the issue tracker (SECOPS-006) with a named owner.

Fixes reach customers as a new AMI version on AWS Marketplace, with a short advisory
naming the affected and fixed versions (ATS-009). `liftproof version` reports the running
version and the exact AWS SDK versions.

## Patching

A deployed instance does not patch itself: it has no route to the Ubuntu archive, and an
image that changed itself would no longer be the one the release scan passed. Operating
system and package fixes reach customers as new AWS Marketplace versions instead:

- Every version is built from a fully upgraded Ubuntu 24.04 LTS and released only after
  Amazon Inspector finds no HIGH or CRITICAL vulnerability in it.
- A new version is released at least once a month, and within 7 days of a fix being
  available for a CRITICAL vulnerability in anything the image ships.
- The image's build date is shown at login and kept in `/etc/mvt/image-built`.

Moving a deployment to a new version is described in the deployment guide.
