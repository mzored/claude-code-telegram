from __future__ import annotations

import json
import multiprocessing
import os
import socket
import tempfile
from pathlib import Path
from queue import Empty
from typing import Any

import pytest

from src.policy_gate.config import GateConfig
from src.policy_gate.executors import MockExecutor
from src.policy_gate.main import serve_policy_gate
from src.policy_gate.rpc import (
    MAX_FRAME_BYTES,
    ControllerGateRpcClient,
    GateRpcAuthorizationError,
    GateRpcProtocolError,
    GateRpcRejectedError,
    PublicGateRpcClient,
    _action_from_wire,
)
from src.policy_gate.service import PolicyConfig, PolicyGateService
from src.policy_gate.store import GateStore
from src.policy_gate.types import (
    ActionBinding,
    ActionOrigin,
    AdminDraft,
    AdminKind,
    ExternalActionConfirmation,
    ExternalActionLink,
    Operation,
    Scope,
    TrustedReference,
    canonical_json,
    digest,
)

GATE_KEY = "rpc-gate-key-" + "r" * 40


def _serve_gate_process(
    socket_path: str,
    database_path: str,
    controller_pid: int,
    client_gid: int,
    ready: Any,
    stop: Any,
    results: Any,
) -> None:
    store = GateStore(Path(database_path), GATE_KEY)
    executor = MockExecutor()
    service = PolicyGateService(
        store,
        executor,
        policy=PolicyConfig(enabled_operations=frozenset(Operation)),
    )
    config = GateConfig(
        data_dir=Path(database_path).parent,
        database_key_file=Path(database_path).parent.parent / "unused-key",
        socket_path=Path(socket_path),
        public_uid=os.getuid(),
        controller_uid=os.getuid(),
        client_gid=client_gid,
    )
    try:
        serve_policy_gate(
            service,
            config,
            controller_pid=controller_pid,
            stop_signal=stop,
            ready_signal=ready,
            poll_interval=0.05,
        )
    finally:
        results.put(len(executor.calls))
        store.close()


def _attempt_controller_from_wrong_pid(socket_path: str, result: Any) -> None:
    try:
        client = ControllerGateRpcClient(Path(socket_path))
        client.prepare_admin(
            TrustedReference("managed_chat", "chat-ref-rpc"),
            AdminDraft(AdminKind.BLOCK),
            owner_id=101001,
            control_chat_id=101001,
            preview_message_id=1,
        )
    except GateRpcAuthorizationError:
        result.put("denied")
    except Exception:
        result.put("wrong_error")
    else:
        client.close()
        result.put("authorized")


def _raw_request(path: Path, wire: bytes) -> dict[str, object]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(3)
    try:
        connection.connect(str(path))
        connection.sendall(wire)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while b"\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        connection.close()
    line, separator, _ = bytes(response).partition(b"\n")
    assert separator == b"\n"
    decoded = json.loads(line.decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def test_canonical_json_rejects_duplicate_keys_after_unicode_normalization() -> None:
    with pytest.raises(ValueError, match="normalization"):
        canonical_json({"\u00e9": 1, "e\u0301": 2})


def test_legacy_public_wire_requires_the_narrow_public_compatibility_path() -> None:
    current = ActionBinding.create(
        subject_id="subject-legacy-rpc",
        connection_id="connection-rpc",
        conversation_id=202002,
        update_id=51,
        request_id="REQ-LEGACY-RPC",
        operation=Operation.TASK_CREATE,
        arguments={"title": "Recover old public action", "due_date": None},
        processing_authorization_version="integration-v2",
        processing_authorization_revision=2,
        processor_purpose="external task creation",
    )
    fields = current.as_dict(include_action_id=False)
    fields.pop("origin")
    legacy_wire = {"action_id": digest(fields), **fields}

    # Controller/external routes use the default strict parser and cannot
    # interpret a missing origin as owner_external.
    with pytest.raises(GateRpcProtocolError):
        _action_from_wire(legacy_wire)

    recovered = _action_from_wire(legacy_wire, allow_legacy_public=True)
    assert recovered.uses_legacy_public_identity
    assert recovered.origin is ActionOrigin.PUBLIC_SENDER
    assert recovered.as_dict() == legacy_wire


def test_mocked_gate_process_enforces_rpc_and_peer_boundary(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    stop = context.Event()
    results = context.Queue()
    intruder_result = context.Queue()

    with tempfile.TemporaryDirectory(
        prefix="pg-", dir=str(Path("/tmp").resolve())
    ) as run_dir:
        socket_path = Path(run_dir) / "g.sock"
        process = context.Process(
            target=_serve_gate_process,
            args=(
                str(socket_path),
                str(tmp_path / "rpc-gate.db"),
                os.getpid(),
                os.getgid(),
                ready,
                stop,
                results,
            ),
        )
        process.start()
        try:
            assert ready.wait(10), "Policy Gate did not bind its Unix socket"
            assert process.is_alive()

            noncanonical = (
                b'{"operation": "allowed_actions", "payload": {}, '
                b'"role": "public", "version": 1}\n'
            )
            assert _raw_request(socket_path, noncanonical) == {
                "error": "invalid_request",
                "ok": False,
            }

            extra_field = {
                "version": 1,
                "role": "public",
                "operation": "allowed_actions",
                "payload": {
                    "subject_id": "subject-rpc",
                    "processing_authorization_version": "integration-v2",
                    "extra": True,
                },
            }
            assert _raw_request(
                socket_path, canonical_json(extra_field).encode("utf-8") + b"\n"
            ) == {"error": "invalid_request", "ok": False}

            oversized = b"x" * (MAX_FRAME_BYTES + 1) + b"\n"
            assert _raw_request(socket_path, oversized) == {
                "error": "invalid_request",
                "ok": False,
            }

            intruder = context.Process(
                target=_attempt_controller_from_wrong_pid,
                args=(str(socket_path), intruder_result),
            )
            intruder.start()
            intruder.join(10)
            assert intruder.exitcode == 0
            assert intruder_result.get(timeout=3) == "denied"

            public = PublicGateRpcClient(socket_path)
            controller = ControllerGateRpcClient(socket_path)
            assert controller.opened_by_pid == os.getpid()
            assert not os.get_inheritable(controller.fileno())
            public.register_subject(
                "subject-rpc",
                {"managed_chat": "chat-ref-rpc", "action": "action-ref-rpc"},
            )
            assert public.activate_receipt(
                "subject-rpc",
                version="integration-v2",
                revision=1,
                processor_purposes={
                    "Google Calendar": ("meeting options",),
                    "Todoist": ("external task creation",),
                },
            )
            assert Operation.TASK_CREATE not in public.allowed_actions(
                "subject-rpc", "integration-v2", 1
            )

            prepared = controller.prepare_admin(
                TrustedReference("managed_chat", "chat-ref-rpc"),
                AdminDraft(
                    AdminKind.GRANT,
                    operation=Operation.TASK_CREATE,
                    scope=Scope.BOUNDED,
                    remaining_uses=1,
                ),
                owner_id=101001,
                control_chat_id=101001,
                preview_message_id=77,
            )
            assert prepared.preview["remaining_uses"] == 1
            confirmed = controller.confirm_admin(
                prepared.intent_id,
                owner_id=101001,
                control_chat_id=101001,
                preview_message_id=77,
            )
            assert confirmed.outcome == "applied"
            assert Operation.TASK_CREATE in public.allowed_actions(
                "subject-rpc", "integration-v2", 1
            )

            binding = ActionBinding.create(
                subject_id="subject-rpc",
                connection_id="connection-rpc",
                conversation_id=101001,
                update_id=500,
                request_id="request-rpc",
                operation=Operation.TASK_CREATE,
                arguments={"title": "Mocked RPC action", "due_date": None},
                processing_authorization_version="integration-v2",
                processing_authorization_revision=1,
                processor_purpose="external task creation",
            )
            assert public.submit_action(binding).outcome == "verified_success"
            assert public.erase_subject("subject-rpc") == "erased"
            assert not public.activate_receipt(
                "subject-rpc",
                version="integration-v2",
                revision=2,
                processor_purposes={"Todoist": ("external task creation",)},
            )
            assert public.allowed_actions("subject-rpc", "integration-v2", 2) == ()
            controller.close()
            with pytest.raises(GateRpcAuthorizationError):
                ControllerGateRpcClient(socket_path)
        finally:
            stop.set()
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)

        assert process.exitcode == 0
        try:
            assert results.get(timeout=3) == 1
        except Empty:
            pytest.fail("Policy Gate process did not report executor calls")


def test_exact_external_stage_is_controller_only_and_preserves_binding(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    stop = context.Event()
    results = context.Queue()
    with tempfile.TemporaryDirectory(
        prefix="pg-u4-", dir=str(Path("/tmp").resolve())
    ) as run_dir:
        socket_path = (Path(run_dir) / "g.sock").resolve(strict=False)
        process = context.Process(
            target=_serve_gate_process,
            args=(
                str(socket_path),
                str(tmp_path / "rpc-gate-u4.db"),
                os.getpid(),
                os.getgid(),
                ready,
                stop,
                results,
            ),
        )
        process.start()
        try:
            assert ready.wait(10), "Policy Gate did not bind its Unix socket"
            public = PublicGateRpcClient(socket_path)
            public.register_subject(
                "subject-u4",
                {"request": "REQ-EXTERNAL-RPC-A"},
            )
            assert public.activate_receipt(
                "subject-u4",
                "integration-v2",
                2,
                {"Todoist": ("external task creation",)},
            )
            binding = ActionBinding.create(
                subject_id="subject-u4",
                connection_id="connection-u4",
                conversation_id=202002,
                update_id=41,
                request_id="REQ-EXTERNAL-RPC-A",
                operation=Operation.TASK_CREATE,
                arguments={"title": "Owner-only exact task", "due_date": None},
                processing_authorization_version="integration-v2",
                processing_authorization_revision=2,
                processor_purpose="external task creation",
                origin=ActionOrigin.OWNER_EXTERNAL,
            )
            # The generic public RPC never stages or submits an owner-external
            # binding, even before an external candidate exists.
            assert not public.stage_action(binding)
            assert public.submit_action(binding).outcome == "denied"
            rejected_public = {
                "version": 1,
                "role": "public",
                "operation": "stage_owner_exact_action",
                "payload": {
                    "request_reference": {
                        "kind": "request",
                        "value": "REQ-EXTERNAL-RPC-A",
                    },
                    "binding": binding.as_dict(),
                },
            }
            assert _raw_request(
                socket_path,
                canonical_json(rejected_public).encode("utf-8") + b"\n",
            ) == {"error": "unauthorized", "ok": False}

            rejected_internal = {
                "version": 1,
                "role": "public",
                "operation": "_submit_owner_external_action",
                "payload": {"binding": binding.as_dict()},
            }
            assert _raw_request(
                socket_path,
                canonical_json(rejected_internal).encode("utf-8") + b"\n",
            ) == {"error": "unauthorized", "ok": False}

            malformed_public = {
                "version": 1,
                "role": "public",
                "operation": "stage_action",
                "payload": {
                    "binding": binding.as_dict(),
                    "external_link": {
                        "link_identity": "a" * 64,
                        "source_digest": "b" * 64,
                    },
                },
            }
            assert _raw_request(
                socket_path,
                canonical_json(malformed_public).encode("utf-8") + b"\n",
            ) == {"error": "invalid_request", "ok": False}

            origin_flip = binding.as_dict()
            origin_flip["origin"] = ActionOrigin.PUBLIC_SENDER.value
            assert _raw_request(
                socket_path,
                canonical_json(
                    {
                        "version": 1,
                        "role": "public",
                        "operation": "submit_action",
                        "payload": {"binding": origin_flip},
                    }
                ).encode("utf-8")
                + b"\n",
            ) == {
                "ok": True,
                "result": {
                    "action_id": binding.action_id,
                    "outcome": "binding_mismatch",
                },
            }

            controller = ControllerGateRpcClient(socket_path)
            external_link = ExternalActionLink("a" * 64, "b" * 64)
            assert controller.stage_owner_exact_action(
                TrustedReference("request", "REQ-EXTERNAL-RPC-A"),
                binding,
                external_link,
            )
            with pytest.raises(GateRpcRejectedError):
                controller.prepare_admin(
                    TrustedReference("action", binding.action_id),
                    AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
                    owner_id=101001,
                    control_chat_id=101001,
                    preview_message_id=90,
                )
            preview = controller.prepare_external_admin(
                TrustedReference("action", binding.action_id),
                AdminDraft(AdminKind.GRANT, scope=Scope.EXACT),
                owner_id=101001,
                control_chat_id=101001,
                preview_message_id=90,
                external_link=external_link,
                minimum_confirmation_sequence=1,
            )
            assert (
                controller.confirm_admin(
                    preview.intent_id,
                    owner_id=101001,
                    control_chat_id=101001,
                    preview_message_id=90,
                ).outcome
                == "denied"
            )
            result = controller.confirm_external_admin(
                preview.intent_id,
                owner_id=101001,
                control_chat_id=101001,
                preview_message_id=90,
                external_confirmation=ExternalActionConfirmation(external_link, 2),
            )
            assert result.outcome == "executed"
            assert public.submit_action(binding).outcome == "denied"
            with pytest.raises(GateRpcProtocolError):
                controller._call(
                    "confirm_external_admin",
                    {
                        "intent_id": preview.intent_id,
                        "owner_id": 101001,
                        "control_chat_id": 101001,
                        "preview_message_id": 90,
                        "external_confirmation": "not-an-external-confirmation",
                    },
                )
            controller.close()
        finally:
            stop.set()
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join(5)
        assert process.exitcode == 0
        assert results.get(timeout=3) == 1
