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

## Run the local candidate image (explicit opt-in)

The local testing wrapper uses the candidate image, a read-only source checkout, no host engine socket, dropped capabilities and dedicated Podman cache volumes. It refuses to run without `--candidate`. The default is **no network**; Cargo dependency/advisory resolution may fail if caches are cold. Use `--allow-network` **only on a segmented development/security VM with restricted outbound access**. Both modes remain untrusted developer experiments, not protected Forgejo evidence.

```bash
bash scripts/security/run-static-container.sh \\
  --image localhost/vaulty/security-static:sec01a \\
  --candidate --mode static-pr
# If required after firewall/network isolation review:
bash scripts/security/run-static-container.sh \\
  --image localhost/vaulty/security-static:sec01a \\
  --candidate --mode static-pr --allow-network
```

Never mount real Vaulty data, token sockets, the host container-engine socket or signing credentials. Named Cargo caches are **not shared** between untrusted CI jobs; this wrapper is for single-owner local smoke testing only.

### Example commands after Zot has authenticated TLS

The following is a **template** and must not be executed against the existing provisional HTTP registry as a trusted distribution:

```bash
REGISTRY='registry.example.tld'
LOCAL='localhost/vaulty/security-static:sec01a'
REMOTE="$REGISTRY/vaulty/security-static:sec01a"
podman login "$REGISTRY"                     # interactive, no password in shell args
podman tag "$LOCAL" "$REMOTE"
podman push --digestfile /tmp/vaulty-sec01a-push.digest "$REMOTE"
cat /tmp/vaulty-sec01a-push.digest           # capture and independently verify
# On the isolated Forgejo runner, after review:
podman pull "$REGISTRY/vaulty/security-static@sha256:<approved-64-hex>"
```

Use a **separate, narrowly scoped publisher identity** and an isolated runner read/pull identity. Store the verified exact image digest (including registry and repository) in the security approval inventory only after vulnerability scanning, provenance review, a smoke run and reviewer sign-off. Do not copy the example mutable tag into the runner label.
