# SEC-00 — Security infrastructure preparation acceptance

**Package**: SEC-00. **Current disposition**: SOURCE CANDIDATE / NOT MERGED / NOT VERIFIED ON DEVELOPMENT MACHINE, FORGEJO RUNNER OR GITHUB ACTIONS. Update only with actual evidence linked to the tested commit.

| ID | Acceptance condition | State at PR creation | Evidence required |
| --- | --- | --- | --- |
| SEC00-A01 | Five Rust manifests and current browser path enumerated; all five committed Cargo.lock files present | IMPLEMENTED IN CANDIDATE | validator, generated security-probes lockfile, `--locked` CI smoke |
| SEC00-A02 | Machine-readable pending/approved tool and OCI digest contract | IMPLEMENTED IN CANDIDATE | JSON negative tests |
| SEC00-A03 | Setup plan and opt-in Debian/Ubuntu prerequisite installation | IMPLEMENTED IN CANDIDATE | clean-host operator invocation |
| SEC00-A04 | Local readiness CLI, check-versions fail-closed, Rust baseline command | IMPLEMENTED IN CANDIDATE | exit-code tests + operator evidence |
| SEC00-A05 | Read-only/offline digest-bound local container contract | IMPLEMENTED IN CANDIDATE | command validation + future image execution |
| SEC00-A06 | Forgejo manual smoke workflow and runner trust rules | IMPLEMENTED IN CANDIDATE | real Forgejo manual run, runner config review |
| SEC00-A07 | GitHub manual lightweight smoke without homelab | IMPLEMENTED IN CANDIDATE | GitHub workflow_dispatch result after merge |
| SEC00-A08 | Dedicated heavy/hardware/release lab policy | DOCUMENTED, NOT PROVISIONED | Ansible/VM configuration + isolation review in later SEC-01 |
| SEC00-A09 | TLS Zot registry, built/pinned images, protected runner pool | NOT IMPLEMENTED | SEC-01A/D infrastructure evidence |
| SEC00-A10 | Actual PR scans, fuzz, CodeQL/OSV, SBOM/signing | NOT IMPLEMENTED | SEC-01A–D independent acceptance |

## Immediate tests

```sh
bash scripts/security/bootstrap-dev.sh --profile minimal --plan
bash scripts/security/run.sh contract
bash scripts/security/doctor.sh
# Negative — MUST fail with exit 78:
bash scripts/security/run.sh pr
bash scripts/security/run.sh release-verify
# Negative — MUST fail (unapproved pins):
bash scripts/security/check-versions.sh
```

The readiness workflow, if green, proves only that the **preparation contract** was validated. Do not mark automated security testing as present. Never promote `CI_PASSED` to `VERIFIED` without matching evidence, and do not close OPEN-01/OPEN-15 or G1–G3.

## Review required before merge

- Confirm shell scripts cannot accidentally enable PR scanning, production release signing or hardware actions.
- Verify all pinned values are null when still pending, no fake digest/tool version claims, and wrong pins are rejected.
- Review runner/registry trust boundary and current homelab HTTP Zot exception.
- Confirm the existing CI, cryptographic reference, test fixtures, hardware evidence and release blockers are unchanged.
- Pin the reviewed SEC-00 commit and record local contract test outputs; leave missing GitHub/Forgejo/VM evidence marked unverified.
