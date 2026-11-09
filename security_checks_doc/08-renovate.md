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
