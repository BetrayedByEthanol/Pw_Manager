# Security OCI image build contract (SEC-00)

No usable custom image or Containerfile is approved or shipped in SEC-00. SEC-01A–D must add images separately after selecting verified tool versions and base-image digests.

| Planned image | Owner | CI trust class |
| --- | --- | --- |
| `vaulty/security-static` | SEC-01A | PR, untrusted, no secrets |
| `vaulty/security-fuzz` | SEC-01B | heavy, untrusted, no secrets |
| `vaulty/security-analysis` | SEC-01C | heavy, untrusted, no secrets |
| `vaulty/security-release` | SEC-01D | protected release only |

## Build and publishing requirements

1. Use a reviewed base image specified by immutable digest; pin all bundled tools and verify source plus SHA-256 or a stronger authenticated supplier attestation.
2. Build with rootless Podman or an appropriately isolated build VM. Do not mount the host Podman/Docker socket in untrusted workflow jobs.
3. Run independent image vulnerability scans and produce an SBOM. Capture the complete built image digest (not the mutable tag).
4. Publish through authenticated **TLS** Zot registry access. The current provisional Zot HTTP/insecure-client configuration **must not** be considered a trusted release-security channel.
5. Verify the image digest after pulling; store it in `.security/tools.lock.json` only after review.
6. For signing and provenance, use a protected release identity separated from PR runners. Do not give production vault credentials, FIDO2 secrets, or signing identities to general-purpose CI.
7. Roll back by selecting a previously reviewed immutable digest; no automatic floating-tag rollout.

Forgejo labels are configured on the runner host, not in this repository. Provision runner classes as separate VMs or equivalent strong isolation. A `runs-on` value alone proves neither runner registration nor protected execution.

The `scripts/security/run-container.sh` wrapper requires a fully qualified `@sha256:` image reference and uses a read-only checkout, no network, and no privilege escalation. Only the `contract` subcommand is implemented at this stage.
