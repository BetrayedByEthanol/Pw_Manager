# OCI security container — local build and Zot deployment

**Status:** `containers/security/Containerfile.static` is a buildable candidate source definition. No image has been built, scanned, signed, approved or published as part of committing this file.

## Build prerequisites

Use rootless Podman on a dedicated builder, with privileged networking and registry access confined to a protected build environment. Obtain **independently verified SHA-256 digest references** for matching Debian Bookworm x86_64 `rust:1.99.1` and `node:22` images from your registry metadata; never use a mutable tag or the illustrative placeholders below as proof of identity.

```bash
RUST_BASE='docker.io/library/rust@sha256:<verified-64-hex>'
NODE_BASE='docker.io/library/node@sha256:<verified-64-hex>'
# Replace placeholders after reviewing registry manifest + image provenance.
podman pull "$RUST_BASE"
podman pull "$NODE_BASE"
bash scripts/security/build-static-image.sh "$RUST_BASE" "$NODE_BASE" localhost/vaulty/security-static:sec01a
```

`build-static-image.sh` refuses tag-only base inputs and uses `--pull=never`. The image bundles native Rust, Python/Semgrep, Node/npm CI-locked lint tools and upstream SHA-256-verified cargo-deny/Gitleaks binaries. The unreviewed Semgrep transitive wheels and unprovisioned OCI base digests block *trusted* publication at this stage.

## Verify locally before publication

```bash
podman image inspect localhost/vaulty/security-static:sec01a
podman run --rm localhost/vaulty/security-static:sec01a python3 --version
podman run --rm localhost/vaulty/security-static:sec01a semgrep --version
# Use the reviewed image digest and the existing read-only container wrapper:
bash scripts/security/run-container.sh --image REGISTRY/REPOSITORY@sha256:<approved-digest> --mode contract
```

The SEC-00 wrapper also requires the image reference to be in the **approved** `.security/tools.lock.json`. A placeholder or merely syntactically valid digest is intentionally rejected. Approval must follow independent test, vulnerability scan, SBOM/provenance evidence and exact digest verification.

## Zot deployment

1. Enable authenticated TLS on Zot; the current provisional insecure HTTP LAN setup must **not** be promoted to a security-image trust root.
2. Provision a narrowly scoped OCI **publisher** identity on the dedicated builder, with no access from untrusted PR jobs.
3. Verify the SBOM and vulnerability report; record accepted exceptions explicitly.
4. Publish by immutable digest, pull and verify digest from a different verification machine.
5. Configure the Forgejo `vaulty-pr` label on an isolated runner to point to the exact approved digest.
6. Remove publisher credentials from the builder after publication and rotate by policy. Use the previous approved digest to roll back.

The OCI image build is deliberately **not** performed inside a PR job with access to a host Podman/Docker socket.
