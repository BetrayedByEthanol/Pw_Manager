# Git repository — source of truth

SEC-01A adds:

| Path | Purpose |
| --- | --- |
| `.security/sec01a-static.json` | Candidate exact tool versions and upstream verified prebuilt binary digests |
| `.security/tools.lock.json` | SEC-00 approval inventory; only artifact hashes actually verified may be approved |
| `deny.toml` | Rust license/advisory/ban/source policy |
| `.gitleaks.toml` | Default secret rules; no broad suppressions |
| `.security/semgrep/*.yml` | Vaulty-specific browser, Python and Rust security patterns |
| `eslint.config.mjs` | Browser JS security rules |
| `package.json`, `package-lock.json` | Exact top-level versions, npm transitive integrity lock |
| `scripts/security/run-static.sh` | Shared local/Forgejo/GitHub implementation |
| `containers/security/Containerfile.static` | Candidate static-analysis OCI build |
| `.forgejo/workflows/sec01a-static-security.yml` | PR/push and manual static scan; requires isolated runner |
| `.github/workflows/sec01a-security-manual.yml` | Manual hosted fallback only |
| `renovate.json` | Renovate proposal configuration, does not install/enable bot |

The Rust packages are **not** a workspace. Iterate over all five `Cargo.toml` paths in SEC-00's inventory. Keep the existing `extenstion/` spelling until a dedicated migration. Do not copy real vault files into checkouts or upload PRF, PIN or recovery secrets as evidence.

## Edit / review process

1. Open a dedicated PR for each scanner upgrade or version change.
2. Update both candidate and approved tool records; independently verify the artifact checksum rather than copying a guessed hash.
3. Run `bash scripts/security/run.sh contract` then `bash scripts/security/run.sh static-pr` on the reviewed commit.
4. Rebuild and scan the OCI image when dependencies or Dockerfile change; do not quietly retag.
5. Record the PR SHA, checker version, exact command, result, finding category and decision in the acceptance register. Include rollback and policy-exception rationale.
6. Update Forgejo branch protection only after an actual passing run from the isolated runner on the source-of-truth repository.

Avoid suppressing existing findings globally. A scanner pass is evidence for the tested source at that tool version, not a cryptographic review approval.
