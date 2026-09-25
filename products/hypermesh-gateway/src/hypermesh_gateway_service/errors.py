"""Door errors. OpenAI shape on /v1/*; sibling routes keep ``detail``."""

from __future__ import annotations

NO_ACTIVE_LEASE_MESSAGE = (
    "No active paid lease for this API key. "
    "Start a lease at https://portal.test.hyperme.sh/dashboard/hypermesh/renter/catalog"
)
INVALID_API_KEY_MESSAGE = "Invalid API key"
TENANT_MISMATCH_MESSAGE = "X-Tenant-ID does not match this credential"
LEASE_NOT_OWNED_MESSAGE = "lease_id is not owned by this API key"


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
