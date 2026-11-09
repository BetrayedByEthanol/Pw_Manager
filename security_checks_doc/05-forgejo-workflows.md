# Forgejo Actions — static PR scan

Workflow: `.forgejo/workflows/sec01a-static-security.yml`

Triggers: pull requests, pushes to `main`, and manual dispatch. The workflow declares `runs-on: vaulty-pr`, which must be registered on the Forgejo runner host with a **reviewed digest-pinned static security image**. The workflow does not deploy images, install production keys or exercise physical FIDO2.

The workflow runs the **actual checks**, not just a preparatory JSON validator:

```bash
bash scripts/security/run.sh contract
python3 scripts/security/check-static-versions.py
bash scripts/security/run.sh static-pr
```

Results: Clippy per independent Cargo package, cargo-deny per package, Gitleaks over the full Git checkout, Semgrep over source code, ESLint and Mozilla web-ext lint.

## Configure and run

1. Publish approved static image and configure the Forgejo runner as documented in [04-forgejo-runner.md](04-forgejo-runner.md).
2. Verify the checkout action points to reviewed bytes, and the PR checkout is the exact source head.
3. Forgejo → Vaulty repository → Actions → workflow **SEC-01A static security** → Run workflow.
4. Inspect each step and record the commit/hash, verdict, and any failures in `docs/security/assurance/`.
5. If all checks run and pass, enable branch protection requiring the `static-security` check on `main`.

**Never set a required check before the runner works.** Otherwise all PRs can hang. A missing runner, stale advisory feed or skipped check must be `INCOMPLETE`, not `PASS`.

CI logs are sensitive; scanners may report matching substrings. Gitleaks uses `--redact`. Do not upload raw scanner reports or live secrets indiscriminately. Retain redacted artifacts with bounded retention and explicit review.
