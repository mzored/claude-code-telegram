"""Policy Gate process lifecycle with injected policy and storage dependencies."""

from __future__ import annotations

import os
import signal
import threading
from typing import Protocol

from src.policy_gate.calendar import GoogleCalendarApi
from src.policy_gate.config import GateConfig
from src.policy_gate.executors import MockExecutor
from src.policy_gate.rpc import PolicyGateRpcServer, StopSignal
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.transport import (
    GatePeerAuthorizer,
    OwnershipSetter,
    bind_unix_listener,
    remove_bound_socket,
)
from src.policy_gate.types import Operation


class ReadySignal(Protocol):
    def set(self) -> None: ...


def serve_policy_gate(
    service: PolicyGateService,
    config: GateConfig,
    *,
    controller_pid: int,
    stop_signal: StopSignal,
    ready_signal: ReadySignal | None = None,
    poll_interval: float = 0.2,
    ownership_setter: OwnershipSetter = os.chown,
) -> None:
    """Run the fixed Gate server in its dedicated caller-owned process."""

    listener = bind_unix_listener(
        config.socket_path,
        config.client_gid,
        ownership_setter=ownership_setter,
    )
    try:
        server = PolicyGateRpcServer(
            service,
            listener,
            GatePeerAuthorizer(
                public_uid=config.public_uid,
                controller_uid=config.controller_uid,
                controller_pid=controller_pid,
            ),
        )
        if ready_signal is not None:
            ready_signal.set()
        server.serve_forever(stop_signal, poll_interval=poll_interval)
    finally:
        listener.close()
        remove_bound_socket(config.socket_path)


def run() -> None:
    """Start the mock-only Gate process with every operation disabled."""

    os.umask(0o077)
    config = GateConfig.from_environment()
    try:
        controller_pid = int(os.environ["POLICY_GATE_CONTROLLER_PID"])
    except (KeyError, ValueError) as exc:
        raise ValueError(
            "POLICY_GATE_CONTROLLER_PID must be a positive integer"
        ) from exc
    if controller_pid <= 0:
        raise ValueError("POLICY_GATE_CONTROLLER_PID must be a positive integer")
    store = GateStore(config.data_dir / "gate.db", config.read_database_key())
    calendar_api = (
        GoogleCalendarApi(config.read_calendar_credentials())
        if config.calendar.enabled
        else None
    )
    policy = PolicyConfig(
        enabled_operations=(
            frozenset({Operation.MEETING_OPTIONS, Operation.MEETING_SCHEDULE})
            if config.calendar.enabled
            else frozenset()
        ),
        calendar=config.calendar,
    )
    service = PolicyGateService(
        store, MockExecutor(), policy=policy, calendar_api=calendar_api
    )
    stop = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    try:
        serve_policy_gate(
            service,
            config,
            controller_pid=controller_pid,
            stop_signal=stop,
        )
    finally:
        store.close()


if __name__ == "__main__":
    run()
