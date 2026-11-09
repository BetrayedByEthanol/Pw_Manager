"""V03-D pure offline receipt classification and no-overwrite regressions."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location(
    "v03d_capture", Path(__file__).with_name("v03d_capture.py"))
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class ReceiptTests(unittest.TestCase):
    GOOD = mod.FINISHED
    READY = mod.READY
    def receipt_output(self, *trailing):
        return "\n".join((self.READY, *trailing)) + "\n"
    def terminal(self, reason):
        return f"V03-C: FAIL_CLOSED: {reason}; no session or credential authorized"

    def test_baseline_does_not_count_security_authorization(self):
        self.assertEqual(mod.classify("baseline", 0, self.receipt_output(self.GOOD), ""),
                         ("LOCAL_IDLE_OBSERVATION_REPORTED", "NONE"))
        self.assertEqual(mod.classify("lock", 0, self.receipt_output(self.GOOD), ""),
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
                self.assertEqual(mod.classify(mode, 2, self.receipt_output(), self.terminal(reason)),
                                 ("LOCAL_TERMINAL_EVENT_REPORTED", reason))

    def test_wrong_event_or_unspecified_failure_is_incomplete(self):
        self.assertEqual(mod.classify("suspend", 2, self.receipt_output(), self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))
        self.assertEqual(mod.classify("lock", 2, self.receipt_output(), self.terminal("SNAPSHOT_REJECTED")),
                         ("INCOMPLETE", "SNAPSHOT_REJECTED"))
        self.assertEqual(mod.classify("lock", 2, self.receipt_output(), "fido2 pin leaked"),
                         ("INCOMPLETE", "UNCLASSIFIED"))
        self.assertEqual(mod.classify("lock", 0, self.receipt_output(), self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))
        self.assertEqual(mod.classify("baseline", 2, self.receipt_output(), self.terminal("SESSION_LOCK")),
                         ("INCOMPLETE", "SESSION_LOCK"))

    def test_missing_or_extra_readiness_cannot_be_counted_as_event_evidence(self):
        self.assertEqual(
            mod.classify("lock", 2, "", self.terminal("SESSION_LOCK")),
            ("INCOMPLETE", "READINESS_NOT_OBSERVED"),
        )
        self.assertEqual(
            mod.classify("baseline", 0, self.GOOD, ""),
            ("INCOMPLETE", "READINESS_NOT_OBSERVED"),
        )
        self.assertEqual(
            mod.classify("lock", 2, self.receipt_output("UNEXPECTED"),
                         self.terminal("SESSION_LOCK")),
            ("INCOMPLETE", "SESSION_LOCK"),
        )
        self.assertEqual(
            mod.classify("baseline", 0, self.receipt_output(self.GOOD, "EXTRA"), ""),
            ("INCOMPLETE", "UNCLASSIFIED"),
        )

    def fake(self, snippet: str) -> list[str]:
        return [sys.executable, "-u", "-c", snippet]

    def test_delayed_readiness_precedes_operator_action_marker(self):
        checkpoints = []
        start = time.monotonic()
        command = self.fake(
            "import time,sys;"
            "time.sleep(0.1);"
            f"print({self.READY!r},flush=True);"
            "time.sleep(0.1);"
            f"print({self.terminal('SESSION_LOCK')!r},file=sys.stderr,flush=True);"
            "sys.exit(2)"
        )
        result = mod.run_observation(
            command, "lock", 1, readiness_timeout=2,
            on_ready=lambda: checkpoints.append(time.monotonic() - start),
        )
        self.assertEqual(result, (
            "LOCAL_TERMINAL_EVENT_REPORTED", "SESSION_LOCK", 2, True, True,
        ))
        self.assertEqual(len(checkpoints), 1)
        self.assertGreaterEqual(checkpoints[0], 0.08)

    def test_startup_snapshot_failure_never_prompts_and_stays_incomplete(self):
        callbacks = []
        command = self.fake(
            "import sys;"
            "print('V03-C: FAIL_CLOSED: UNSAFE_SESSION; no session or credential authorized',"
            "file=sys.stderr,flush=True);sys.exit(2)"
        )
        status, reason, _, ready, prompted = mod.run_observation(
            command, "lock", 1, readiness_timeout=1,
            on_ready=lambda: callbacks.append("UNEXPECTED"),
        )
        self.assertEqual((status, reason), ("INCOMPLETE", "READINESS_NOT_OBSERVED"))
        self.assertFalse(ready)
        self.assertFalse(prompted)
        self.assertEqual(callbacks, [])

    def test_missing_readiness_times_out_and_kills_the_observer(self):
        callbacks = []
        command = self.fake("import time;time.sleep(10)")
        start = time.monotonic()
        result = mod.run_observation(
            command, "suspend", 1, readiness_timeout=0.1,
            on_ready=lambda: callbacks.append("UNEXPECTED"),
        )
        self.assertEqual(result[0:2], ("INCOMPLETE", "READINESS_TIMEOUT"))
        self.assertFalse(result[3])
        self.assertFalse(result[4])
        self.assertEqual(callbacks, [])
        self.assertLess(time.monotonic() - start, 2)

    def test_spoofed_or_incorrect_readiness_is_never_prompted(self):
        for message in ["RUNNING_OBSERVATION", "V03-C: OBSERVED_ONLY",
                        self.READY + " untrusted"]:
            with self.subTest(message=message):
                callbacks = []
                command = self.fake(
                    f"print({message!r}, flush=True);"
                    "import time;time.sleep(5)"
                )
                result = mod.run_observation(
                    command, "lock", 1, readiness_timeout=1,
                    on_ready=lambda: callbacks.append("UNEXPECTED"),
                )
                self.assertEqual(result[0:2], (
                    "INCOMPLETE", "READINESS_PROTOCOL_INVALID",
                ))
                self.assertFalse(result[3])
                self.assertEqual(callbacks, [])

    def test_baseline_requires_handshake_but_never_prompts_a_lifecycle_action(self):
        callbacks = []
        command = self.fake(
            "import time;"
            f"print({self.READY!r},flush=True);"
            "time.sleep(0.05);"
            f"print({self.GOOD!r},flush=True)"
        )
        result = mod.run_observation(
            command, "baseline", 1, readiness_timeout=1,
            on_ready=lambda: callbacks.append("READY"),
        )
        self.assertEqual(result, (
            "LOCAL_IDLE_OBSERVATION_REPORTED", "NONE", 0, True, False,
        ))
        self.assertEqual(callbacks, ["READY"])

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
