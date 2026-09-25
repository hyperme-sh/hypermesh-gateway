"""Door errors. OpenAI shape on /v1/*; sibling routes keep ``detail``."""

from __future__ import annotations

import os

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
