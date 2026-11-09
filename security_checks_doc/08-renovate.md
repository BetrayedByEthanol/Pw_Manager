# Renovate — setup and controlled dependency updates

Repository file: `renovate.json`. This is **configuration only**: it does not install, authorize or run a Renovate bot.

## Choose integration

**Preferred:** Self-host Renovate with a restricted Forgejo bot account, if the Forgejo version/API and Renovate platform support your chosen configuration. For GitHub-only mirror updates, GitHub's Renovate app can be connected by an authorized repository administrator; mirror PRs must not become the authoritative implementation source.

## Operational checklist

1. Install Renovate in an isolated container/VM (not the PR runner), using a reviewed, immutable image and version. Review the current Renovate/Forgejo compatibility matrix.
2. Provision a **dedicated bot identity**, repo-scoped pull-request permissions, no production credentials, no release signing or Zot publisher permissions.
3. Configure the Forgejo platform URL and API token via protected environment/secret delivery outside the Vaulty repo; do **not** commit either.
4. Use `renovate.json` to discover Cargo lockfiles for five independent projects, npm lockfile, image base references and workflow actions.
5. Perform a dry run with dashboard and at most three concurrent update PRs. Verify no automatic merges.
6. For each PR, update audited version/checksum records, run SEC-01A checks, rebuild the OCI image, verify evidence and manually approve before merge.
7. Schedule periodic bot credential rotation, image rebuild and review of upstream security advisories.

**Tool-update gap:** `.security/sec01a-static.json` is a bespoke version inventory. Renovate does not automatically keep those records aligned; maintain them in the tool update PR until an independently tested custom regex manager is configured. Never enable broad automatic replacement of security-tool digests.

No Renovate installation or connection was made by SEC-01A.

## Concrete Forgejo dry-run procedure

Official Renovate supports **`platform=forgejo`** (do not use `gitea` for a Forgejo instance). Use a separate bot account with the supported Forgejo PAT permissions: `repo` read/write, `user` read, and, where required by the instance version, `issue` read/write and `organization` read. Scope access to the intended Vaulty repository; never reuse an administrator's token. If a second GitHub.com token is needed to avoid release-lookup rate limits, it should be **read-only** and stored as a separate secret.

Create an operator-managed, mode-0600 env file **outside this checkout**:

```sh
install -d -m 0700 "$HOME/.config/vaulty-renovate"
install -m 0600 /dev/null "$HOME/.config/vaulty-renovate/renovate.env"
# Edit securely in an editor; NEVER commit this file:
# RENOVATE_PLATFORM=forgejo
# RENOVATE_ENDPOINT=https://forgejo.example/api/v1
# RENOVATE_REPOSITORIES=owner/Pw_Manager
# RENOVATE_TOKEN=<bot PAT>
# RENOVATE_AUTODISCOVER=false
# RENOVATE_DRY_RUN=full
```

Then, after independently verifying an immutable Renovate image digest and the Forgejo TLS endpoint:

```sh
RENOVATE_IMAGE='ghcr.io/renovatebot/renovate@sha256:<reviewed-64-hex>'
podman pull "$RENOVATE_IMAGE"
podman run --rm --read-only --cap-drop=all --security-opt=no-new-privileges \\
  --env-file "$HOME/.config/vaulty-renovate/renovate.env" \\
  --tmpfs /tmp:rw,nosuid,nodev,size=1g \\
  "$RENOVATE_IMAGE"
```

The code above is an **operator template**, not an executed configuration; substitute your actual Forgejo hostname, repository and image digest. Container runtime DNS, CA certificates, network isolation and writable caches must be validated in the deployment environment. `RENOVATE_DRY_RUN=full` must remain set for first evaluation; remove it **only** after reviewing the logs and bot permissions. For production scheduling, run the verified container under a dedicated Ansible-managed systemd timer or isolated CI schedule, never in an untrusted PR job.

Before enabling scheduled runs, confirm no autopmerge and that an update PR cannot update reviewed security-image digests or tool checksum metadata without explicit human review.
