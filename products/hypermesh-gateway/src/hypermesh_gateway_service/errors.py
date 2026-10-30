"""Door errors. OpenAI shape on /v1/*; sibling routes keep ``detail``."""

from __future__ import annotations

import os

from fastapi import HTTPException
from hypermesh_ticket import INSTANCE_NOT_READY

CATALOG_PATH = "/dashboard/hypermesh/renter/catalog"
INVALID_API_KEY_MESSAGE = "Invalid API key"
TENANT_MISMATCH_MESSAGE = "X-Tenant-ID does not match this credential"
LEASE_NOT_OWNED_MESSAGE = "lease_id is not owned by this API key"


def portal_origin() -> str:
    """Browser origin for the 402 catalog link. Empty when unset.

    Test deploy sets ``HYPERMESH_PORTAL_ORIGIN=https://portal.test.hyperme.sh``.
    Prod sets its own origin. The door does not hardcode either host.
    """

    return os.environ.get("HYPERMESH_PORTAL_ORIGIN", "").strip().rstrip("/")


def no_active_lease_message() -> str:
    origin = portal_origin()
    link = f"{origin}{CATALOG_PATH}" if origin else CATALOG_PATH
    return (
        "No active paid lease for this API key. "
        f"Start a lease at {link}"
    )


def model_not_found_message(requested: str, available: list[str]) -> str:
    listed = ", ".join(available) if available else "(none)"
    return (
        f"The model `{requested}` is not served by an active lease. "
        f"Available models: {listed}."
    )


class DoorError(Exception):
    def __init__(self, status_code: int, message: str, code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.code = code


def openai_error_body(message: str, code: str) -> dict[str, dict[str, str]]:
    return {
        "error": {
            "message": message,
            "type": "invalid_request_error",
            "code": code,
        }
    }


INSTANCE_NOT_READY_CODE = "instance_not_ready"
NOT_READY_REASON_HEADER = "X-Hypermesh-Not-Ready"
NOT_READY_RETRY_AFTER_S = 5

# Reasons a later call can succeed without anyone acting: the WireGuard peer
# has not handshaked yet, the host port is not listening yet, or the host
# answered 5xx (llama-server answers 503 while it loads the model).
RETRYABLE_NOT_READY = frozenset({"peer_down", "host_unreachable"})


def not_ready_retryable(reason: str) -> bool:
    if reason in RETRYABLE_NOT_READY:
        return True
    return reason.startswith("host_status_5")


def instance_not_ready(reason: str) -> HTTPException:
    """409 instance not ready with a stable reason and, when retryable, Retry-After.

    The ``detail`` stays ``instance not ready`` for existing callers. On
    ``/v1/*`` the app handler adds the OpenAI error object with code
    ``instance_not_ready``.
    """

    headers = {NOT_READY_REASON_HEADER: reason}
    if not_ready_retryable(reason):
        headers["Retry-After"] = str(NOT_READY_RETRY_AFTER_S)
    return HTTPException(status_code=409, detail=INSTANCE_NOT_READY, headers=headers)


def instance_not_ready_body(reason: str | None) -> dict[str, object]:
    """OpenAI error object plus the legacy ``detail`` key."""

    known = reason or "unspecified"
    return {
        "error": {
            "message": INSTANCE_NOT_READY,
            "type": "invalid_request_error",
            "code": INSTANCE_NOT_READY_CODE,
            "reason": known,
            "retryable": not_ready_retryable(known),
        },
        "detail": INSTANCE_NOT_READY,
    }
