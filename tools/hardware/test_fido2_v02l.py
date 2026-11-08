"""V02-L-A/B offline negative and failure-gate tests: NEVER access FIDO2 hardware."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fido2_v02j as j
import fido2_v02l as l


class NativeNegativeHarnessTests(unittest.TestCase):
    def setUp(self):
        self.session = j.initialize("vaulty-test.localhost")
        self.session["credentials"] = {}
        for role, token in (("primary", b"alpha"), ("backup", b"beta")):
            self.session["credentials"][role] = {
                "credential_id_b64": j._b64(b"test-credential-" + token),
                "public_key_pem": (
                    "-----BEGIN PUBLIC KEY-----\n" + token.decode() +
                    "\n-----END PUBLIC KEY-----\n"),
                "rp_id": self.session["rp_id"],
                "test_only": True,
                "attestation_chain_verified": False,
            }

    def authdata(self, flags: int = 0x05) -> bytes:
        return (l.hashlib.sha256(self.session["rp_id"].encode()).digest()
                + bytes((flags,)) + bytes(4))

    def test_rp_up_uv_signed_flag_requirements(self):
        l._require_signed_flags(self.authdata(), self.session["rp_id"])
        for flags in (0, 1, 4, 2, 0x80):
            with self.subTest(flags=flags), self.assertRaisesRegex(
                    j.ProbeError, "missing UP or UV"):
                l._require_signed_flags(self.authdata(flags), self.session["rp_id"])
        with self.assertRaisesRegex(j.ProbeError, "RP hash mismatch"):
            l._require_signed_flags(self.authdata(), "different.localhost")
        with self.assertRaisesRegex(j.ProbeError, "too short"):
            l._require_signed_flags(b"\0" * 36, self.session["rp_id"])

    def fake_verifier_run(self, args, *, data=None, timeout=90, interactive=False):
        if "-G" in args:
            lines = Path(args[args.index("-i") + 1]).read_text("ascii").splitlines()
            self.assertEqual(len(lines), 4)
            self.assertTrue(interactive)
            self.assertIn("-v", args)
            self.assertIn("uv=true", args)
            self.expected = [lines[0], lines[1], j._b64(self.authdata()),
                             j._b64(b"synthetic-signature")]
            return ("\n".join(self.expected + [j._b64(b"\x63" * 32)]) + "\n").encode()
        if "-V" in args:
            self.assertIn("-h", args)
            self.assertIn("-p", args)
            self.assertIn("-v", args)
            self.assertFalse(interactive)
            self.assertNotIn(b"\x63" * 32, data)
            parsed = data.decode().splitlines()
            is_wrong_public = "other-test-public.pem" in " ".join(args)
            if parsed == self.expected and not is_wrong_public:
                return b""
            raise j.ProbeError(l.EXACT_VERIFIER_FAILURE)
        raise AssertionError(f"unexpected command {args}")

    def test_negative_verifier_matrix_only_after_positive_control(self):
        with patch.object(j, "_tool", side_effect=lambda x: x), \
             patch.object(j, "_run", side_effect=self.fake_verifier_run):
            actual = l.verifier_negatives(self.session, "primary", "/dev/hidraw999")
        self.assertEqual(actual["positive_signed_up_uv"], "OBSERVED")
        self.assertEqual(set(actual), {"positive_signed_up_uv", *l.CASES})
        for name in l.CASES:
            self.assertEqual(actual[name], l.REJECTED)
        self.assertNotIn("synthetic-signature", json.dumps(actual))
        self.assertNotIn("test-credential-", json.dumps(actual))
        self.assertNotIn("vaulty-test.localhost", json.dumps(actual))

    def test_positive_verification_failure_aborts_without_false_rejection(self):
        def rejected(*args, **kwargs):
            raise j.ProbeError(l.EXACT_VERIFIER_FAILURE)
        with patch.object(j, "_tool", side_effect=lambda x: x), \
             patch.object(j, "_run", side_effect=self.fake_verifier_run), \
             patch.object(l, "_verify", side_effect=rejected):
            with self.assertRaises(j.ProbeError):
                l.verifier_negatives(self.session, "primary", "/dev/hidraw42")

    def test_unexpected_verifier_acceptance_is_a_failure(self):
        with tempfile.TemporaryDirectory(prefix="vaulty-v02l-test-") as d:
            key = Path(d) / "key.pem"
            key.write_text("synthetic")
            with patch.object(l, "_verify", return_value=None):
                self.assertEqual(l._expect_rejection(key, ["x", "y", "z", "k"]), l.ACCEPTED)
            with patch.object(l, "_verify", side_effect=j.ProbeError("timed out")):
                self.assertEqual(l._expect_rejection(key, ["x", "y", "z", "k"]), l.UNCERTAIN)
            with patch.object(l, "_verify",
                              side_effect=j.ProbeError(l.EXACT_VERIFIER_FAILURE)):
                self.assertEqual(l._expect_rejection(key, ["x", "y", "z", "k"]), l.REJECTED)

    def test_mutation_and_missing_credentials_fail_closed(self):
        self.assertNotEqual(l._mutate_b64(j._b64(b"abcd"), offset=1), j._b64(b"abcd"))
        with self.assertRaises(j.ProbeError):
            l._mutate_b64(j._b64(b"abc"), offset=4)
        self.session["credentials"].pop("backup")
        with self.assertRaisesRegex(j.ProbeError, "missing/untrusted"):
            l.verifier_negatives(self.session, "primary", "/dev/hidraw99")

    def test_wrong_device_requires_control_and_refuses_undifferentiated_success(self):
        values = [bytearray(b"\x33"*32), bytearray(b"\x44"*32)]
        trace = []
        def fake_measure(session, role, entry, device, assurance):
            trace.append(role)
            if role == "primary":
                raise j.ProbeError(l.EXACT_VERIFIER_FAILURE)
            return values.pop(0)
        with patch.object(j, "_measure", side_effect=fake_measure):
            result = l.wrong_device_probe(self.session, "primary", "backup", "/dev/hidraw7")
        self.assertEqual(trace, ["backup", "primary", "backup"])
        self.assertEqual(result, {
            "control_before": "OBSERVED",
            "target_credential_on_other_key": "LOCAL_DEVICE_REJECTION_UNCLASSIFIED",
            "control_after": "OBSERVED",
        })
        with self.assertRaisesRegex(j.ProbeError, "different"):
            l.wrong_device_probe(self.session, "primary", "primary", "/dev/hidraw7")

        tokens = [bytearray(b"\x55"*32), bytearray(b"\x66"*32), bytearray(b"\x77"*32)]
        with patch.object(j, "_measure", side_effect=tokens):
            failed = l.wrong_device_probe(self.session, "primary", "backup", "/dev/hidraw7")
        self.assertEqual(failed["target_credential_on_other_key"], l.ACCEPTED)
        self.assertEqual(tokens, [bytearray(32)] * 3)

    def test_wrong_device_negative_is_indeterminate_on_timeout(self):
        seq = [bytearray(b"\x01"*32), j.ProbeError("FIDO2 tool unavailable, timed out or device removed"),
               bytearray(b"\x02"*32)]
        with patch.object(j, "_measure", side_effect=seq):
            r = l.wrong_device_probe(self.session, "primary", "backup", "/dev/hidraw99")
        self.assertEqual(r["target_credential_on_other_key"], l.UNCERTAIN)

    def test_redacted_receipt_cannot_approve_security_or_disclose_secrets(self):
        report = l._receipt("a"*40, "verifier")
        serialized = json.dumps(report)
        for expected in ('"open_15": "BLOCKED"', '"open_01": "BLOCKED"',
                         '"entry_route_ready": false',
                         '"actual_invalid_pin_attempted": false',
                         '"production_runtime_replay_protection_tested": false',
                         '"browser_webauthn_tested": false',
                         '"status": "INCOMPLETE"'):
            self.assertIn(expected, serialized)
        for forbidden in ("hidraw", "credential_id_b64", "public_key_pem",
                          "challenge", "prf_output", "pin_value", "rp_id"):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_local_receipt_persisted_only_after_opt_in_and_redacted(self):
        with tempfile.TemporaryDirectory(prefix="vaulty-v02l-private-") as d:
            dest = Path(d) / "evidence.json"
            args = l.parse(["verifier", "--session", str(Path(d)/"private-session.json"),
                            "--role", "primary", "--device", "/dev/hidraw7",
                            "--receipt", str(dest), "--hardware-test"])
            good = {"positive_signed_up_uv": "OBSERVED",
                    **{case: l.REJECTED for case in l.CASES}}
            with patch.object(l, "_live_gate"), \
                 patch.object(l, "_source_head", return_value="a"*40), \
                 patch.object(l, "_session", return_value=self.session), \
                 patch.object(l, "_confirm"), \
                 patch.object(l, "verifier_negatives", return_value=good):
                code = l.run_live(args)
            self.assertEqual(code, 0)
            result = json.loads(dest.read_text("utf-8"))
            self.assertEqual(result["status"], "LOCAL_NEGATIVE_OBSERVATIONS_CAPTURED")
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
            self.assertNotIn("/dev/hidraw7", dest.read_text())
            self.assertNotIn("vaulty-test.localhost", dest.read_text())
            with patch.object(l, "_live_gate"), patch.object(l, "_source_head", return_value="a"*40), \
                 patch.object(l, "_session", return_value=self.session), \
                 patch.object(l, "_confirm"):
                with self.assertRaises(FileExistsError):
                    l.run_live(args)  # Never overwrite an earlier evidence receipt.

    def test_live_opt_in_ci_root_and_missing_device_gates(self):
        args = l.parse(["verifier", "--session", "/tmp/session.json", "--role", "primary",
                        "--device", "/dev/hidraw0", "--receipt", "/tmp/receipt.json"])
        with self.assertRaisesRegex(j.ProbeError, "hardware-test"):
            l.run_live(args)
        with patch.dict(os.environ, {"CI": "true"}), patch("os.geteuid", return_value=1000):
            with self.assertRaisesRegex(j.ProbeError, "forbidden in CI"):
                l._live_gate("/dev/hidraw999", require_device=True)
        with patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(j.ProbeError, "root"):
                l._live_gate("/dev/hidraw999", require_device=True)
        with patch("os.geteuid", return_value=1000), patch.dict(os.environ,
             {"CI": "", "GITHUB_ACTIONS": "", "FORGEJO_ACTIONS": ""}):
            with self.assertRaisesRegex(j.ProbeError, "console"):
                l._live_gate("/dev/hidraw999", require_device=False)

    def test_missing_device_check_never_calls_token(self):
        with tempfile.TemporaryDirectory(prefix="vaulty-v02l-empty-") as d:
            # No runtime vault verdict: this is just an explicit path precheck.
            args = l.parse(["unavailable", "--device", "/dev/hidraw99999",
                            "--receipt", str(Path(d) / "receipt.json"), "--hardware-test"])
            with patch.object(l, "_live_gate"), \
                 patch.object(l, "_source_head", return_value="b"*40), \
                 patch.object(l, "_confirm"), \
                 patch.object(j, "_run", side_effect=AssertionError("device access")):
                self.assertEqual(l.run_live(args), 0)
            data = json.loads((Path(d)/"receipt.json").read_text())
            self.assertEqual(data["cases"]["missing_path_precheck"], "LOCAL_PRECHECK_REJECTED")
            self.assertFalse(data["entry_route_ready"])

    def test_clean_git_source_required_and_dirty_rejected(self):
        class P:
            def __init__(self, stdout):
                self.stdout = stdout
        with patch.object(l.subprocess, "run", side_effect=[
                P(b"f"*40 + b"\n"), P(b" M tools/hardware/fido2_v02l.py\n")]):
            with self.assertRaisesRegex(j.ProbeError, "clean Git"):
                l._source_head()


if __name__ == "__main__":
    unittest.main()
