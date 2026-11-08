"""Offline V02-J harness safety/provenance tests. NO authenticators are used."""
from __future__ import annotations

import base64
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fido2_v02j as harness


class IsolatedHardwareHarnessTests(unittest.TestCase):
    def setUp(self):
        self.session = harness.initialize("vaulty-test.localhost")
        self.session["credentials"] = {
            "primary": {
                "credential_id_b64": base64.b64encode(b"synthetic-cred-a").decode("ascii"),
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n",
                "rp_id": self.session["rp_id"],
                "test_only": True, "attestation_chain_verified": False,
            },
            "backup": {
                "credential_id_b64": base64.b64encode(b"synthetic-cred-b").decode("ascii"),
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n",
                "rp_id": self.session["rp_id"],
                "test_only": True, "attestation_chain_verified": False,
            },
        }

    def test_synthetic_session_is_not_vault_and_has_no_implicit_credentials(self):
        x = harness.initialize("vaulty-test.localhost")
        self.assertEqual(x["credentials"], {})
        self.assertTrue(x["review_only"])
        self.assertEqual(set(x["entries"]), set(harness.ENTRIES))
        self.assertEqual(len({v["id"] for v in x["entries"].values()}), 2)
        for v in x["entries"].values():
            self.assertNotEqual(v["slots"]["primary"], v["slots"]["backup"])
        self.assertNotIn("READY", json.dumps(x))

    def test_entry_slot_credential_rp_and_assurance_salt_isolation(self):
        context, salt = harness._context(self.session, "primary", "alpha", purpose=1, assurance=1)
        self.assertEqual(len(salt), 32)
        self.assertEqual(salt, harness.hashlib.sha256(b"WebAuthn PRF\0" + context).digest())
        for role, entry, purpose, assurance in [
            ("backup", "alpha", 1, 1), ("primary", "beta", 1, 1),
            ("primary", "alpha", 2, 1), ("primary", "alpha", 1, 2),
        ]:
            self.assertNotEqual(salt, harness._context(self.session, role, entry, purpose=purpose,
                                                       assurance=assurance)[1])
        x = harness.copy.deepcopy(self.session)
        x["rp_id"] = "different.localhost"
        x["credentials"]["primary"]["rp_id"] = x["rp_id"]
        self.assertNotEqual(salt, harness._context(x, "primary", "alpha", purpose=1, assurance=1)[1])

    def test_absent_backup_never_passes_as_provisioned_entry_slot(self):
        del self.session["credentials"]["backup"]
        with self.assertRaisesRegex(harness.ProbeError, "not separately registered"):
            harness._context(self.session, "backup", "alpha", purpose=1, assurance=1)

    def test_input_spoof_or_bad_rp_blocks_before_any_device_call(self):
        x = harness.copy.deepcopy(self.session)
        x["credentials"]["primary"]["rp_id"] = "wrong.localhost"
        with self.assertRaises(harness.ProbeError):
            harness._context(x, "primary", "alpha", purpose=1, assurance=1)
        x = harness.copy.deepcopy(self.session)
        x["credentials"]["primary"]["credential_id_b64"] = "!!!"
        with self.assertRaises(harness.ProbeError):
            harness._context(x, "primary", "alpha", purpose=1, assurance=1)

    def test_hardware_gate_rejects_ci_and_missing_tty_and_non_device_path(self):
        with patch.dict(os.environ, {"CI": "true"}):
            with self.assertRaisesRegex(harness.ProbeError, "refused in CI"):
                harness._hardware_gate("/dev/hidraw0")
        with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": "", "FORGEJO_ACTIONS": ""}):
            with self.assertRaisesRegex(harness.ProbeError, "hidraw"):
                harness._hardware_gate("/tmp/not-a-real-device")
        self.assertNotIn("register", harness.initialize("vaulty-test.localhost"))

    def test_signed_assertion_parser_requires_challenge_rp_format_and_32_byte_output(self):
        challenge = bytes([3]) * 32
        good = b"\n".join([
            harness._b64(challenge).encode(), b"vaulty-test.localhost",
            harness._b64(b"authdata").encode(),
            harness._b64(b"signature").encode(),
            harness._b64(bytes([9]) * 32).encode(),
        ]) + b"\n"
        self.assertEqual(len(harness._assertion_result(good, challenge=challenge,
                                                      rp_id="vaulty-test.localhost")), 32)
        for mutated in (
            good.replace(b"vaulty-test.localhost", b"evil.localhost"),
            good.replace(harness._b64(challenge).encode(), harness._b64(bytes(32)).encode()),
            good + b"extra\n",
            good.replace(harness._b64(bytes([9])*32).encode(), harness._b64(b"too-short").encode()),
            good.replace(harness._b64(b"signature").encode(), b"!!!"),
        ):
            with self.subTest(mutated_len=len(mutated)):
                with self.assertRaises(harness.ProbeError):
                    harness._assertion_result(mutated, challenge=challenge,
                                              rp_id="vaulty-test.localhost")

    def test_probe_never_logs_prf_and_wipes_mutable_results(self):
        outputs = [bytearray([1]*32), bytearray([1]*32), bytearray([2]*32)]
        i = iter(outputs)
        with patch.object(harness, "_measure", side_effect=lambda *_a, **_kw: next(i)):
            report = harness.probe(self.session, "primary", "alpha", "/dev/hidraw1",
                                   compare_entry="beta")
        self.assertTrue(report["repeat_prf_stable"])
        self.assertTrue(report["different_entry_prf_distinct"])
        self.assertTrue(report["signature_and_requested_flags_checked"])
        self.assertFalse(report["open_15_approved"])
        self.assertFalse(report["entry_route_ready"])
        self.assertEqual(outputs, [bytearray(32)]*3)
        self.assertNotIn("0101010101", json.dumps(report))
        self.assertNotIn("0202020202", json.dumps(report))

    def test_probe_wipes_results_on_early_failure(self):
        secret = bytearray([0x55]*32)
        with patch.object(harness, "_measure", side_effect=[secret, harness.ProbeError("failed")]):
            with self.assertRaises(harness.ProbeError):
                harness.probe(self.session, "primary", "alpha", "/dev/hidraw1")
        self.assertEqual(secret, bytearray(32))

    def test_measure_requires_verified_signature_and_uv_before_success(self):
        trace = []
        secret = bytes([7])*32
        def fake_run(args, *, data=None, timeout=90, interactive=False):
            trace.append(args)
            if "-G" in args:
                self.assertTrue(interactive)
                self.assertIsNone(data)
                lines = Path(args[args.index("-i")+1]).read_text(encoding="ascii").splitlines()
                return "\n".join([lines[0], lines[1], harness._b64(b"authenticator-data"),
                                   harness._b64(b"signature"), harness._b64(secret)]).encode() + b"\n"
            if "-V" in args:
                self.assertIn("-p", args)
                self.assertIn("-v", args)
                self.assertIn("-h", args)
                return b""
            raise AssertionError("unexpected command")
        with patch.object(harness, "_tool", side_effect=lambda n: n), \
             patch.object(harness, "_run", side_effect=fake_run):
            value = harness._measure(self.session, "primary", "alpha", "/dev/hidraw1", "uv")
        self.assertEqual(value, bytearray(secret))
        self.assertEqual(len(trace), 2)
        self.assertIn("-t", trace[0])
        harness.wipe(value)
        self.assertEqual(value, bytearray(32))

    def test_signed_verification_failure_never_returns_prf_result(self):
        def fake_run(args, *, data=None, timeout=90, interactive=False):
            if "-G" in args:
                self.assertTrue(interactive)
                lines = Path(args[args.index("-i")+1]).read_text(encoding="ascii").splitlines()
                return "\n".join([lines[0], lines[1], harness._b64(b"authdata"),
                                   harness._b64(b"sig"), harness._b64(bytes([5])*32)]).encode()
            raise harness.ProbeError("signature invalid")
        with patch.object(harness, "_tool", side_effect=lambda n: n), \
             patch.object(harness, "_run", side_effect=fake_run):
            with self.assertRaises(harness.ProbeError):
                harness._measure(self.session, "primary", "alpha", "/dev/hidraw1", "uv")

    def test_session_and_receipt_written_privately_outside_repo(self):
        with tempfile.TemporaryDirectory(prefix="vaulty-v02j-test-") as d:
            path = Path(d) / "session.json"
            harness._private_write(path, self.session, new=True)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(harness._read_session(path)["schema"], harness.SCHEMA)
            with self.assertRaises(FileExistsError):
                harness._private_write(path, self.session, new=True)
            harness._private_write(path, harness.initialize("vaulty-test.localhost"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            dest = Path(d) / "link.json"
            dest.symlink_to(path)
            with self.assertRaises(harness.ProbeError):
                harness._safe_path(dest)

    def test_register_requires_distinct_test_credential_and_uses_verify(self):
        src = self.session
        src["credentials"] = {}
        calls = []
        def fake(args, *, data=None, timeout=90, interactive=False):
            calls.append(args)
            if "-M" in args:
                self.assertTrue(interactive)
                self.assertIsNone(data)
                request = Path(args[args.index("-i")+1])
                self.assertEqual(len(request.read_text(encoding="ascii").splitlines()), 4)
                self.assertEqual(stat.S_IMODE(request.stat().st_mode), 0o600)
                return b"attestation-placeholder"
            if "-V" in args:
                self.assertIn("-h", args)
                self.assertIn("-v", args)
                return (harness._b64(b"new-synthetic-credential") +
                        "\n-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n").encode()
            raise AssertionError("bad command")
        with patch.object(harness, "_tool", side_effect=lambda n: n), \
             patch.object(harness, "_run", side_effect=fake):
            result = harness.register_credential(src, "primary", "/dev/hidraw1")
        self.assertFalse(result["credentials"]["primary"]["attestation_chain_verified"])
        self.assertEqual(src["credentials"], {})
        self.assertEqual(len(calls), 2)
        with self.assertRaises(harness.ProbeError):
            harness.register_credential(result, "primary", "/dev/hidraw1")


if __name__ == "__main__":
    unittest.main()
