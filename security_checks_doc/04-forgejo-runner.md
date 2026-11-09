# Forgejo/Gitea runner — prepare isolated static-scan execution

Forgejo is the intended source-of-truth CI. Gitea Actions has similar workflow syntax, but behavior/runner plugins must be independently tested before reuse. **Do not use the current generic `docker` label as a privileged security runner.**

## Ansible / runner host preparation

Provision a dedicated disposable VM or equivalent strong isolation for `vaulty-pr` with restricted networking. Run the Forgejo runner under a non-privileged account, a bounded container runtime, and no API credentials other than those needed for runner registration and read-only checkout.

Example runner-label entry *after* a candidate image is reviewed, pushed over TLS and pinned:

```yaml
runner:
  labels:
    - "vaulty-pr:docker://registry-01.example/vaulty/security-static@sha256:<approved-64-hex>"
```

Replace the registry host and digest; this is not a usable configuration until the image exists and is independently verified. Do not use `host` labels, `privileged=true`, mount `/var/run/docker.sock`, or expose Zot publisher or release signing keys.

Isolate untrusted PR source from privileged networks. Restrict resource consumption (CPU, memory, process count, timeouts), use disposable workspaces and document the credential/sanitization boundary. Podman-backed Forgejo job containers still require careful daemon and label configuration; labels alone do not enforce isolation.

## Bring-up checklist

1. Configure authenticated registry pull over TLS.
2. Verify the runner's container runtime can fetch the reviewed image by digest.
3. Register `vaulty-pr` on the intended Forgejo repository and confirm it appears as online.
4. Run workflow `sec01a-static-security.yml` manually on a harmless candidate commit.
5. Verify full Git history is available for Gitleaks and that the job has Node and all pinned scanners.
6. Attempt a deliberately broken test branch and confirm the check fails and blocks promotion.
7. Only then configure Forgejo branch protection to require `static-security`; verify it is actually enforced.

Keep any image build/publish worker separate from this PR runner. Rotate runner registration token on deprovisioning. A skipped or queued job is not a security scan.
