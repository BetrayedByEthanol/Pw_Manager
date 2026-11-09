"""V03-B offline-only failure-injection regression tests; never contact D-Bus."""
import asyncio
import dataclasses
import importlib.util
import os
from pathlib import Path
import sys
import unittest

SPEC = importlib.util.spec_from_file_location(
    "v03b_logind", Path(__file__).with_name("v03b_logind.py"))
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

OWNER = ":1.42"
SESSION = "/org/freedesktop/login1/session/_32"


def snap(**override):
    value = dict(uid=os.getuid(), locked=False, active=True, state="active",
                 kind="x11", can_lock=True, session_class="user", remote=False,
                 seat=("seat0", "/org/freedesktop/login1/seat/seat0"),
                 sleeping=False, shutting_down=False)
    value.update(override)
    return value


class FakeBus:
    def __init__(self, *, signal_at_match=None, state=None):
        self.connected = False
        self.callback = None
        self.matches = []
        self.current_owner = OWNER
        self.current_session = SESSION
        self.state = state or snap()
        self.signal_at_match = signal_at_match
        self.closed = False
    async def connect(self):
        self.connected = True
    def on_message(self, cb):
        self.callback = cb
    async def add_match(self, rule):
        self.matches.append(rule)
        if self.signal_at_match and len(self.matches) == 4:
            self.push(self.signal_at_match)
    def push(self, signal):
        raw = type("FakeMessage", (), dict(
            message_type=1, sender=signal.sender, path=signal.path,
            interface=signal.interface, member=signal.member,
            signature=signal.signature, body=signal.body))
        self.callback(raw)
    _MessageType = type("MessageType", (), {"SIGNAL": 1})
    async def owner(self):
        return self.current_owner
    async def session_by_pid(self):
        return self.current_session
    async def snapshot(self, session):
        assert session == SESSION
        return dict(self.state)
    def close(self):
        self.closed = True
        self.connected = False


def sig(member, *, sender=OWNER, path=SESSION, interface=m.SESSION_IFACE,
        signature="", body=()):
    return m.Signal(sender, path, interface, member, signature, body)


class GateTests(unittest.TestCase):
    def bound(self):
        g = m.Decision()
        g.pin(OWNER, SESSION)
        g.initializing = False
        return g

    def test_initial_session_must_be_local_active_unlocked_and_can_lock(self):
        self.assertTrue(m.positive_snapshot(snap()))
        for variant in [
            dict(uid=os.getuid()+1), dict(locked=True), dict(locked=None),
            dict(active=False), dict(state="closing"), dict(kind="tty"),
            dict(can_lock=False), dict(session_class="greeter"),
            dict(remote=True), dict(seat=("", "/org/freedesktop/login1/seat/")),
            dict(seat=("seat0", "/wrong")),
            dict(sleeping=True), dict(shutting_down=True),
        ]:
            with self.subTest(variant=variant):
                self.assertFalse(m.positive_snapshot(snap(**variant)))

    def test_lock_unlock_and_manager_sleep_shutdown_always_fail_closed(self):
        signals = [
            sig("Lock"), sig("Unlock"),
            sig("PrepareForSleep", path=m.MANAGER, interface=m.MANAGER_IFACE,
                signature="b", body=(True,)),
            sig("PrepareForSleep", path=m.MANAGER, interface=m.MANAGER_IFACE,
                signature="b", body=(False,)),
            sig("PrepareForShutdown", path=m.MANAGER, interface=m.MANAGER_IFACE,
                signature="b", body=(True,)),
            sig("SessionRemoved", path=m.MANAGER, interface=m.MANAGER_IFACE,
                signature="so", body=("2", SESSION)),
        ]
        for value in signals:
            with self.subTest(signal=value):
                with self.assertRaises(m.MonitoringStopped):
                    self.bound().accept(value)

    def test_invalid_sender_on_relevant_signal_fails_closed(self):
        for value in [
            sig("Lock", sender=":1.999"),
            sig("PrepareForSleep", sender=":1.999", path=m.MANAGER,
                interface=m.MANAGER_IFACE, signature="b", body=(True,)),
            sig("Lock", signature="b", body=(True,)),
            sig("PrepareForSleep", path=m.MANAGER, interface=m.MANAGER_IFACE,
                signature="s", body=("true",)),
            sig("PropertiesChanged", path=SESSION, interface=m.PROPS,
                signature="a", body=()),
        ]:
            with self.subTest(value=value):
                with self.assertRaises(m.MonitoringStopped):
                    self.bound().accept(value)

    def test_name_owner_change_never_allows_recovery(self):
        changed = sig("NameOwnerChanged", sender=m.DBUS,
                      path=m.DBUS_PATH, interface=m.DBUS,
                      signature="sss", body=(m.SERVICE, OWNER, ":1.44"))
        gate = self.bound()
        with self.assertRaisesRegex(m.MonitoringStopped, "OWNER_CHANGED"):
            gate.accept(changed)
        with self.assertRaises(m.MonitoringStopped):
            gate.accept(sig("Unlock"))

    def test_startup_race_or_unsafe_owner_binding_rejected(self):
        gate = m.Decision()
        gate.pin(OWNER, SESSION)
        with self.assertRaisesRegex(m.MonitoringStopped, "STARTUP_RACE"):
            gate.accept(sig("Lock"))
        for owner, path in [("org.freedesktop.login1", SESSION),
                            (OWNER, "/unsafe"), ("hello", SESSION)]:
            with self.assertRaises(m.MonitoringStopped):
                m.Decision().pin(owner, path)

    def test_other_session_lock_does_not_approve_anything(self):
        gate = self.bound()
        gate.accept(sig("Lock", path="/org/freedesktop/login1/session/other"))
        self.assertIsNone(gate.stopped)

    def test_malformed_manager_event_and_property_change_fail_closed(self):
        gate = self.bound()
        with self.assertRaises(m.MonitoringStopped):
            gate.accept(sig("PrepareForSleep", path=m.MANAGER,
                            interface=m.MANAGER_IFACE, signature="b", body=(1,)))
        gate = self.bound()
        with self.assertRaises(m.MonitoringStopped):
            gate.accept(sig("PropertiesChanged", interface=m.PROPS,
                            signature="sa{sv}as", body=(
                                m.SESSION_IFACE, {}, [])))


class ObserverTests(unittest.IsolatedAsyncioTestCase):
    async def test_stable_direct_bus_observation_is_non_authorizing(self):
        bus = FakeBus()
        observer = m.Observer(bus, interval=0.1)
        result = await observer.observe(0.12)
        self.assertEqual(result, "OBSERVED_ONLY")
        self.assertTrue(bus.closed)
        self.assertEqual(len(bus.matches), 4)
        self.assertEqual(observer.gate.owner, OWNER)
        self.assertEqual(observer.gate.session, SESSION)

    async def test_stale_owner_rechecked_each_poll(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.current_owner = ":1.43"
        with self.assertRaisesRegex(m.MonitoringStopped, "BINDING_CHANGED"):
            await watcher.verify_health()
        bus.close()

    async def test_inactive_session_or_pending_sleep_blocks_bootstrap(self):
        for state in [snap(active=False), snap(sleeping=True), snap(locked=True)]:
            bus = FakeBus(state=state)
            watcher = m.Observer(bus, interval=0.1)
            with self.assertRaisesRegex(m.MonitoringStopped, "UNSAFE_INITIAL_SESSION"):
                await watcher.observe(0.1)
            self.assertTrue(bus.closed)

    async def test_startup_signal_after_subscribe_aborts_before_active(self):
        bus = FakeBus(signal_at_match=sig("Lock"))
        watcher = m.Observer(bus, interval=0.1)
        with self.assertRaises(m.MonitoringStopped):
            await watcher.observe(0.1)
        self.assertTrue(watcher.gate.initializing)
        # The signal is never treated as proof of successful startup.
        self.assertTrue(bus.closed)

    async def test_lock_signal_after_startup_terminates_on_next_drain(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.push(sig("Lock"))
        with self.assertRaisesRegex(m.MonitoringStopped, "SESSION_LOCK_TRANSITION"):
            await watcher.verify_health()
        bus.close()

    async def test_disconnect_and_signal_queue_overflow_fail_closed(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.connected = False
        with self.assertRaisesRegex(m.MonitoringStopped, "BUS_DISCONNECTED"):
            await watcher.verify_health()
        bus.close()
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        for _ in range(m.MAX_PENDING + 1):
            bus.push(sig("Lock", path="/org/freedesktop/login1/session/other"))
        with self.assertRaisesRegex(m.MonitoringStopped, "EVENT_QUEUE_OVERFLOW"):
            watcher.drain()
        bus.close()

    async def test_boottime_gap_or_clock_regression_is_fail_closed(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        baseline = watcher.last_tick
        from unittest.mock import patch
        with patch.object(m, "boottime", return_value=baseline + 6):
            with self.assertRaisesRegex(m.MonitoringStopped, "WATCHDOG_GAP"):
                await watcher.verify_health()
        bus.close()
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        baseline = watcher.last_tick
        with patch.object(m, "boottime", return_value=baseline - 1):
            with self.assertRaisesRegex(m.MonitoringStopped, "WATCHDOG_GAP"):
                await watcher.verify_health()
        bus.close()

    async def test_malformed_payload_is_rejected_without_materializing_secrets(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.push(sig("Lock", body=("x" * 8192,)))
        with self.assertRaisesRegex(m.MonitoringStopped, "MALFORMED_EVENT"):
            await watcher.verify_health()
        bus.close()

    async def test_owner_changed_event_and_bad_health_snapshot_fail_closed(self):
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.push(sig("NameOwnerChanged", sender=m.DBUS, path=m.DBUS_PATH,
                     interface=m.DBUS, signature="sss",
                     body=(m.SERVICE, OWNER, ":1.50")))
        with self.assertRaisesRegex(m.MonitoringStopped, "OWNER_CHANGED"):
            await watcher.verify_health()
        bus.close()
        bus = FakeBus()
        watcher = m.Observer(bus, interval=0.1)
        await watcher.start()
        bus.state = snap(locked=True)
        with self.assertRaisesRegex(m.MonitoringStopped, "UNSAFE_SESSION"):
            await watcher.verify_health()
        bus.close()

if __name__ == "__main__":
    unittest.main()
