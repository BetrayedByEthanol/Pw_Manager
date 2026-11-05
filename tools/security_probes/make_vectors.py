"""Rebuild *public synthetic* OPEN-01 candidate vectors; needs argon2-cffi."""
from __future__ import annotations
import json
from pathlib import Path
from argon2.low_level import Type, hash_secret_raw
from kek_vectors import derive

# Argon2id sample parameters for deterministic test inputs ONLY; not a
# recommended production memory/time cost. Production parameter review OPEN.
ARG = {"type": "Argon2id", "version": 19, "memory_kib": 8192, "time_cost": 2,
       "parallelism": 1, "hash_len": 32}
salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
def argon_first(password: str) -> str:
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=ARG["time_cost"],
                           memory_cost=ARG["memory_kib"], parallelism=ARG["parallelism"],
                           hash_len=ARG["hash_len"], type=Type.ID, version=ARG["version"]).hex()

C = dict(vault_id="00112233-4455-6677-8899-aabbccddeeff", purpose="wrap-entry-dek")
V = [
    dict(id="default-virtual", mode="two_factor", **C, target_id="entry-alpha", slot_id="slot-alpha-v",
         policy="ENTRY_DEFAULT_VIRTUAL", first_component_hex=bytes(range(32)).hex(),
         prf_component_hex=bytes(range(128,160)).hex()),
    dict(id="default-physical", mode="two_factor", **C, target_id="entry-alpha", slot_id="slot-alpha-p",
         policy="ENTRY_DEFAULT_PHYSICAL", first_component_hex=bytes(range(32)).hex(),
         prf_component_hex=(b"\x55" * 32).hex()),
    dict(id="custom-physical", mode="two_factor", **C, target_id="entry-bravo", slot_id="slot-bravo-p",
         policy="ENTRY_PASSWORD_PHYSICAL", first_component_hex=argon_first("vaulty test entry password"),
         prf_component_hex=(b"\xaa" * 32).hex(),
         argon2id_password="vaulty test entry password", argon2id_salt_hex=salt.hex()),
    dict(id="custom-virtual", mode="two_factor", **C, target_id="entry-charlie", slot_id="slot-charlie-v",
         policy="ENTRY_PASSWORD_VIRTUAL", first_component_hex=argon_first("another public test password"),
         prf_component_hex=(b"\x77" * 32).hex(),
         argon2id_password="another public test password", argon2id_salt_hex=salt.hex()),
    dict(id="code-only-vmk", mode="recovery_code_only", vault_id=C["vault_id"],
         purpose="wrap-vmk", target_id="VMK", slot_id="slot-vmk-code", policy="RECOVERY_CODE_ONLY",
         recovery_code_hex=bytes(range(32,64)).hex()),
    dict(id="code-only-dek", mode="recovery_code_only", **C, target_id="entry-alpha",
         slot_id="slot-alpha-code", policy="RECOVERY_CODE_ONLY",
         recovery_code_hex=bytes(range(32,64)).hex()),
]
for v in V:
    v.update(derive(v))
doc = {"version": "VAULTY-OPEN-01-CANDIDATE-v1", "status": "UNREVIEWED INTEROPERABILITY FIXTURE",
       "argon2id_test_parameters": ARG, "vectors": V}
output = Path(__file__).with_name("fixtures") / "kek_vectors.json"
output.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
print(output)
