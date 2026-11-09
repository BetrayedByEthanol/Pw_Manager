# GitHub Actions — hosted manual-only fallback

Workflow: `.github/workflows/sec01a-security-manual.yml`.

It uses `workflow_dispatch` **only** (no GitHub PR/push scan), `contents: read`, a GitHub-hosted Ubuntu runner, a reviewed checkout action commit, local `npm ci` and verified cargo-deny/Gitleaks upstream archives. It requires **no** internal Zot images, private runner, homelab access, hardware key, signing identity or deployment credentials.

## Run

1. Merge the workflow onto the GitHub default branch (GitHub only offers manual dispatch from the default branch).
2. GitHub → Vaulty repo → **Actions** → **SEC-01A manual static security** → **Run workflow** → select `main` or another available ref.
3. Confirm the run's exact checked-out SHA. If it differs from the intended source, discard and rerun.
4. Check `Validate contracts and candidate tool versions` and `Execute static security analysis` logs; report true exit codes.
5. Log results in the SEC-01A acceptance register. A manual GitHub run is **supplemental evidence** and cannot substitute for protected Forgejo checks.

GitHub uses an explicitly requested `--candidate` install for manual testing. It installs Python Semgrep with a pinned top-level version but without fully hash-locked transitive wheels; treat the supply-chain state as candidate. GitHub runner images and hosted action behavior may change; reverify before relying on results. Do not add privileged tokens to this workflow.
