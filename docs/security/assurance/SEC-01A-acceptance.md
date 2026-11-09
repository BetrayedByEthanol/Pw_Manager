# SEC-01A — Static Security Foundation acceptance (candidate)

**PR #31, not merged; source and documentation candidate.** No Forgejo runner, image, TLS registry, protected branch check or Renovate bot is assumed operational. Tools must be executed and their findings reviewed before changing this disposition.

See the complete per-location runbooks in [security_checks_doc](../../../security_checks_doc/README.md).

- SOURCE: tool versions, binaries' verified upstream digests, lint configs, 5-crate scripts, npm locked graph, OCI build contract, Forgejo/GitHub workflow source and Renovate bot configuration.
- NOT EXECUTED: workstation installation, custom image creation/publication, Forgejo runner, manual GitHub workflow (requires default-branch merge), actual static security scans and reviewed findings.
- NOT APPROVED: cryptographic protocol OPEN-01/OPEN-15, G1–G3 release gates, protected PR enforcement or signed production releases.
- FOLLOW-UP: review Semgrep transitive PyPI wheel hashes; pin OCI base digests with independent provenance; validate the runner and branch protection; record full first-run results in this ledger.

## CI / PR acceptance

Contract/negative-path tests should run on the GitHub mirror's existing security-probes CI; they do not replace Forgejo scanner execution. The SEC-01A Forgejo job uses the dedicated `vaulty-pr` label, not the generic `docker` runner. A queued job is incomplete. The GitHub security scan is `workflow_dispatch` only and cannot be counted as a default pull-request gate.

For acceptance, capture the source SHA, script/tool/image digest, redacted logs, exit code, Forgejo job reference, exact branch protection rule and reviewer disposition. Do not close SEC-01A or promote scanner results to crypto security certification until the required evidence exists.
