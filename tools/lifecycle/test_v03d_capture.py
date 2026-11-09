"""V03-D pure offline receipt classification and no-overwrite regressions."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "v03d_capture", Path(__file__).with_name("v03d_capture.py"))
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class ReceiptTests(unittest.TestCase):
    GOOD = "V03-C: OBSERVED_ONLY; no session or credential authorized"
    def terminal(self, reason):
        return f"V03-C: FAIL_CLOSED: {reason}; no session or credential authorized"

    def test_baseline_does_not_count_security_authorization(self):
        self.assertEqual(mod.classify("baseline", 0, self.GOOD, ""),
                         ("LOCAL_IDLE_OBSERVATION_REPORTED", "NONE"))
        self.assertEqual(mod.classify("lock", 0, self.GOOD, ""),
                         ("INCOMPLETE", "UNCLASSIFIED"))

    def test_only_exact_expected_event_counts(self):
        cases = (
            ("lock", "SESSION_LOCK"),
            ("suspend", "SLEEP_START"),
            ("disconnect", "LOGIND_OWNER_CHANGED"),
            ("disconnect", "BUS_DISCONNECTED"),
        )
        for mode, reason in cases:
            with self.subTest(mode=mode, reason=reason):
                self.assertEqual(mod.classify(mode, 2, "", self.terminal(reason)),
                                 ("LOCAL_TERMINAL_EVENT_REPORTED", reason))

    def test_wrong_event_or_unspecified_failure_is_incomplete(self):
        self.assertEqual(mod.classify("suspend", 2, "", self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))
        self.assertEqual(mod.classify("lock", 2, "", self.terminal("SNAPSHOT_REJECTED")),
                         ("INCOMPLETE", "SNAPSHOT_REJECTED"))
        self.assertEqual(mod.classify("lock", 2, "", "fido2 pin leaked"),
                         ("INCOMPLETE", "UNCLASSIFIED"))
        self.assertEqual(mod.classify("lock", 0, "", self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))
        self.assertEqual(mod.classify("baseline", 2, "", self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))

    def test_evidence_directory_is_private_receipt_exclusive_and_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            os.chmod(folder, 0o700)
            receipt = folder / "receipt.json"
            payload = {"schema": mod.SCHEMA, "status": "INCOMPLETE",
                       "real_vault_loaded_or_unlocked": False}
            mod.write_new(receipt, payload)
            self.assertEqual(json.loads(receipt.read_text()), payload)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            with self.assertRaisesRegex(mod.Refused, "RECEIPT_EXISTS"):
                mod.write_new(receipt, payload)
            self.assertEqual(json.loads(receipt.read_text()), payload)

    def test_world_readable_dir_cannot_hold_security_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            os.chmod(folder, 0o755)
            with self.assertRaisesRegex(mod.Refused, "NOT_PRIVATE"):
                mod.private_parent(folder / "receipt.json")


if __name__ == "__main__":
    unittest.main()
