# Vaulty security toolchain configuration (SEC-00)

**PREPARATION ONLY — not a working security scanner or release gate.** The two JSON files are machine-checked contracts; their unapproved tool versions and unpublished image digests are intentionally null. Do not fill with guessed versions or hashes.

- `tools.lock.json`: proposed tools, source/checksum pinning policy, five existing Rust manifests, four planned OCI images.
- `policy.json`: runner trust classes, disabled gates, evidence fields, production and hardware restrictions.
- `../scripts/security/`: native/local entrypoints, opt-in prerequisite installer, fail-closed scanner dispatch, container wrapper.
- `../tools/security/`: stdlib-only contract validation and negative tests.
- `../docs/ci/SEC-00-security-infrastructure.md`: location-specific preparation runbook and exit criteria.

SEC-01A must select and authenticate exact tool releases and image digests **before** enabling PR gates; SEC-01B/C/D own the remaining toolchain. Values move from `pending`/`unpublished` to `approved`/`published` only together with version/checksum/provenance evidence and a PR review. Scanner exceptions and change-control approvals are separate from the technical lockfile.

Commands (current):
```sh
python3 tools/security/validate_contract.py
python3 -m unittest discover -s tools/security -p 'test_*.py' -v
bash scripts/security/bootstrap-dev.sh --profile minimal --plan
bash scripts/security/doctor.sh
bash scripts/security/run.sh contract
```

`run.sh pr`, `run.sh fuzz-smoke` and `run.sh release-verify` deliberately exit 78 (EX_CONFIG), not success. Manual GitHub/Forgejo workflows validate the SEC-00 contract only; they do **not** perform security scanning.

Existing V02 test vectors, review evidence, and hardware-lab reports are not modified or upgraded to independent assurance by SEC-00.
