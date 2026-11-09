#!/usr/bin/env python3
"""V03-B Linux logind monitor — direct D-Bus, read-only, OBSERVATION ONLY.

This is NOT the trusted Vaulty daemon. It never reports security READY,
unlocks a vault, or installs a privileged session capability. No D-Bus input,
stdout, CLI option or watcher's alive status is accepted by V03-A as proof
that a lifecycle listener is healthy. The application executable is inert.

Optional runtime dependency: dbus-next==0.2.3, installed OUTSIDE the repo.
Offline tests import this module without the dependency or any system bus.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import os
import re
import sys
import time
from typing import Any

SERVICE = "org.freedesktop.login1"
MANAGER = "/org/freedesktop/login1"
MANAGER_IFACE = "org.freedesktop.login1.Manager"
SESSION_IFACE = "org.freedesktop.login1.Session"
PROPS = "org.freedesktop.DBus.Properties"
DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
MAX_PENDING = 128
UNIQUE = re.compile(r"^:[0-9]+\.[0-9]+$")


def boottime() -> float:
    # CLOCK_MONOTONIC may exclude Linux suspend; CLOCK_BOOTTIME includes it.
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise MonitoringStopped("NO_BOOTTIME_CLOCK")
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class MonitoringStopped(Exception):
    """Fixed, non-sensitive failure reason; never propagate D-Bus payload."""


@dataclasses.dataclass(frozen=True)
class Signal:
    sender: str
    path: str
    interface: str
    member: str
    signature: str
    body: tuple[Any, ...]


class Decision:
    """Deterministic signal gate. Only verified service-owner signals count.

    A signal does not grant a capability; *any* relevant lock/unlock/sleep,
    shutdown, owner transition, malformed matching message or unknown state
    stops the observer. A future authenticated in-process daemon must act
    synchronously on these decisions BEFORE authorizing secret operations.
    """
    def __init__(self) -> None:
        self.owner: str | None = None
        self.session: str | None = None
        self.initializing = True
        self.stopped: str | None = None

    def pin(self, owner: str, session: str) -> None:
        if not UNIQUE.fullmatch(owner) or not session.startswith(
            "/org/freedesktop/login1/session/"
        ) or len(session) > 256 or self.stopped:
            self.stop("INVALID_BINDING")
        self.owner, self.session = owner, session

    def stop(self, reason: str) -> None:
        self.stopped = reason
        raise MonitoringStopped(reason)

    def accept(self, message: Signal) -> None:
        if self.stopped:
            raise MonitoringStopped(self.stopped)
        if message.interface == DBUS and message.member == "NameOwnerChanged":
            if (message.sender != DBUS or message.path != DBUS_PATH or
                message.signature != "sss" or len(message.body) != 3):
                self.stop("UNTRUSTED_OWNER_CHANGE")
            if message.body[0] == SERVICE:
                self.stop("OWNER_CHANGED")
            return
        if message.interface == MANAGER_IFACE and message.member in (
            "PrepareForSleep", "PrepareForShutdown", "SessionRemoved",
        ):
            if message.sender != self.owner or message.path != MANAGER:
                self.stop("UNTRUSTED_SIGNAL")
            if self.initializing:
                self.stop("STARTUP_RACE")
            if message.member == "SessionRemoved":
                if (message.signature != "so" or len(message.body) != 2):
                    self.stop("MALFORMED_SIGNAL")
                if message.body[1] == self.session:
                    self.stop("SESSION_REMOVED")
                return
            if (message.signature != "b" or len(message.body) != 1
                or type(message.body[0]) is not bool):
                self.stop("MALFORMED_SIGNAL")
            self.stop("SLEEP_OR_SHUTDOWN")
        if message.interface == SESSION_IFACE and message.member in ("Lock", "Unlock"):
            if message.sender != self.owner:
                self.stop("UNTRUSTED_SIGNAL")
            if self.initializing:
                self.stop("STARTUP_RACE")
            if message.path == self.session:
                if message.signature != "" or message.body:
                    self.stop("MALFORMED_SIGNAL")
                self.stop("SESSION_LOCK_TRANSITION")
            return
        # logind PropertiesChanged can signal an update to LockedHint.
        if message.interface == PROPS and message.member == "PropertiesChanged":
            if message.sender != self.owner:
                return  # unrelated system-bus sender
            if self.initializing:
                self.stop("STARTUP_RACE")
            if message.path in (self.session, MANAGER):
                if message.signature != "sa{sv}as":
                    self.stop("MALFORMED_SIGNAL")
                self.stop("SESSION_PROPERTY_CHANGED")


def positive_snapshot(values: dict[str, Any]) -> bool:
    """Default-deny: require local active unlocked session and idle manager.

    LockedHint is provided by the desktop; it is NOT proof of a trusted
    compositor lock. A missing/unreliable hint must be treated as unsupported.
    """
    return (
        type(values.get("locked")) is bool and values["locked"] is False
        and type(values.get("active")) is bool and values["active"] is True
        and values.get("state") == "active"
        and type(values.get("can_lock")) is bool and values["can_lock"] is True
        and values.get("kind") in ("x11", "wayland")
        and type(values.get("uid")) is int and values["uid"] == os.getuid()
        and type(values.get("sleeping")) is bool and values["sleeping"] is False
        and type(values.get("shutting_down")) is bool
        and values["shutting_down"] is False
    )


class DirectSystemBus:
    """A small direct D-Bus transport, no shell, external JSON or event pipes."""
    def __init__(self) -> None:
        self.bus = None
        self._Message = None
        self._MessageType = None

    async def connect(self) -> None:
        # No import side-effects in offline tests and no production dependency.
        from dbus_next.aio import MessageBus
        from dbus_next import BusType, Message, MessageType
        self._Message, self._MessageType = Message, MessageType
        self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    @property
    def connected(self) -> bool:
        return bool(self.bus and self.bus.connected)

    def on_message(self, callback: Any) -> None:
        assert self.bus is not None
        self.bus.add_message_handler(callback)

    async def call(self, dest: str, path: str, interface: str,
                   method: str, signature: str = "", body: list[Any] | None = None
                   ) -> list[Any]:
        if not self.connected:
            raise MonitoringStopped("BUS_DISCONNECTED")
        assert self.bus is not None and self._Message is not None
        msg = self._Message(destination=dest, path=path, interface=interface,
                            member=method, signature=signature, body=body or [])
        reply = await asyncio.wait_for(self.bus.call(msg), timeout=2.0)
        if (reply is None or reply.message_type != self._MessageType.METHOD_RETURN):
            raise MonitoringStopped("DBUS_QUERY_FAILED")
        return reply.body

    async def add_match(self, rule: str) -> None:
        await self.call(DBUS, DBUS_PATH, DBUS, "AddMatch", "s", [rule])

    async def owner(self) -> str:
        answer = await self.call(DBUS, DBUS_PATH, DBUS, "GetNameOwner",
                                 "s", [SERVICE])
        if len(answer) != 1 or not isinstance(answer[0], str):
            raise MonitoringStopped("INVALID_OWNER")
        return answer[0]

    async def session_by_pid(self) -> str:
        answer = await self.call(SERVICE, MANAGER, MANAGER_IFACE,
                                 "GetSessionByPID", "u", [os.getpid()])
        if len(answer) != 1 or not isinstance(answer[0], str):
            raise MonitoringStopped("INVALID_SESSION")
        return answer[0]

    async def prop(self, path: str, interface: str, name: str) -> Any:
        answer = await self.call(SERVICE, path, PROPS,
                                 "Get", "ss", [interface, name])
        if len(answer) != 1 or not hasattr(answer[0], "value"):
            raise MonitoringStopped("INVALID_PROPERTY")
        return answer[0].value

    async def snapshot(self, session: str) -> dict[str, Any]:
        get = self.prop
        user = await get(session, SESSION_IFACE, "User")
        if not isinstance(user, (list, tuple)) or len(user) != 2:
            raise MonitoringStopped("INVALID_SESSION_UID")
        return {
            "uid": user[0],
            "locked": await get(session, SESSION_IFACE, "LockedHint"),
            "active": await get(session, SESSION_IFACE, "Active"),
            "state": await get(session, SESSION_IFACE, "State"),
            "kind": await get(session, SESSION_IFACE, "Type"),
            "can_lock": await get(session, SESSION_IFACE, "CanLock"),
            "sleeping": await get(MANAGER, MANAGER_IFACE, "PreparingForSleep"),
            "shutting_down": await get(MANAGER, MANAGER_IFACE, "PreparingForShutdown"),
        }

    def close(self) -> None:
        if self.bus is not None:
            self.bus.disconnect()


class Observer:
    def __init__(self, transport: DirectSystemBus, *, interval: float = 2.0) -> None:
        if not 0.1 <= interval <= 10.0:
            raise ValueError("invalid observer interval")
        self.transport = transport
        self.interval = interval
        self.gate = Decision()
        self.events: asyncio.Queue[Signal] = asyncio.Queue(maxsize=MAX_PENDING)
        self.failed: str | None = None
        self.last_tick: float | None = None

    def receive(self, raw: Any) -> None:
        # Called in the bus's own event loop; copies only typed event metadata.
        if self.failed:
            return
        try:
            if raw.message_type != self.transport._MessageType.SIGNAL:
                return
            # PropertiesChanged may contain large untrusted values; ignore
            # their contents, since the boundary stops on the signal itself.
            interface = str(raw.interface)
            member = str(raw.member)
            if interface == PROPS and member == "PropertiesChanged":
                body = ()
            else:
                if len(raw.body) > 3 or any(
                    isinstance(v, str) and len(v) > 256 for v in raw.body
                ):
                    self.failed = "MALFORMED_EVENT"
                    return
                body = tuple(raw.body)
            signal = Signal(str(raw.sender), str(raw.path),
                            interface, member, str(raw.signature), body)
            if self.events.full():
                self.failed = "EVENT_QUEUE_OVERFLOW"
                return
            self.events.put_nowait(signal)
        except Exception:
            self.failed = "MALFORMED_EVENT"

    def drain(self) -> None:
        if self.failed:
            self.gate.stop(self.failed)
        while not self.events.empty():
            self.gate.accept(self.events.get_nowait())

    async def start(self) -> None:
        await self.transport.connect()
        self.transport.on_message(self.receive)
        # Install ALL matches before owner/session queries. During bootstrap,
        # a matching security signal fails initialization rather than being
        # silently dropped. Match the bus owner change first.
        matches = [
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.login1'",
            "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager'",
            "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session'",
            "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.DBus.Properties'",
        ]
        for rule in matches:
            await self.transport.add_match(rule)
            self.drain()
        owner = await self.transport.owner()
        session = await self.transport.session_by_pid()
        self.gate.pin(owner, session)
        if not positive_snapshot(await self.transport.snapshot(session)):
            self.gate.stop("UNSAFE_INITIAL_SESSION")
        if await self.transport.owner() != owner or await self.transport.session_by_pid() != session:
            self.gate.stop("BINDING_CHANGED")
        self.drain()
        if not self.transport.connected:
            self.gate.stop("BUS_DISCONNECTED")
        self.gate.initializing = False
        self.last_tick = boottime()

    async def verify_health(self) -> None:
        # A live connection alone is not a heartbeat. Recheck owner and
        # critical properties, with a bounded query deadline.
        self.drain()
        if not self.transport.connected:
            self.gate.stop("BUS_DISCONNECTED")
        now = boottime()
        if self.last_tick is None or now < self.last_tick or (
            now - self.last_tick > max(5.0, self.interval * 3.0)
        ):
            self.gate.stop("WATCHDOG_GAP")
        owner, session = self.gate.owner, self.gate.session
        if await self.transport.owner() != owner or await self.transport.session_by_pid() != session:
            self.gate.stop("BINDING_CHANGED")
        if not positive_snapshot(await self.transport.snapshot(session)):
            self.gate.stop("UNSAFE_SESSION")
        self.drain()
        self.last_tick = boottime()

    async def observe(self, seconds: float) -> str:
        if not 0.1 <= seconds <= 600:
            raise ValueError("invalid observation duration")
        try:
            await self.start()
            until = time.monotonic() + seconds
            while time.monotonic() < until:
                await self.verify_health()
                await asyncio.sleep(min(self.interval, max(0, until - time.monotonic())))
                self.drain()
            await self.verify_health()
            return "OBSERVED_ONLY"
        except MonitoringStopped:
            raise
        except asyncio.CancelledError:
            raise MonitoringStopped("OBSERVATION_CANCELLED") from None
        except Exception:
            # Never expose D-Bus errors containing session paths or payloads.
            raise MonitoringStopped("BUS_OR_HEALTH_FAILED") from None
        finally:
            self.transport.close()


async def main_async(args: argparse.Namespace) -> int:
    observer = Observer(DirectSystemBus(), interval=args.interval)
    try:
        status = await observer.observe(args.seconds)
        print(f"V03-B: {status}: read-only logind observation; no Vaulty session authorized")
        return 0
    except MonitoringStopped as exc:
        print(f"V03-B: FAIL_CLOSED: {str(exc)}; no Vaulty session authorized",
              file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe-only", action="store_true")
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--interval", type=float, default=2)
    args = parser.parse_args()
    if not args.observe_only:
        parser.error("must explicitly select --observe-only (no vault integration)")
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("requires non-root Linux session")
    try:
        return asyncio.run(main_async(args))
    except ImportError:
        print("V03-B: FAIL_CLOSED: optional dbus-next package unavailable", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("V03-B: FAIL_CLOSED: operator interrupted observation", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
