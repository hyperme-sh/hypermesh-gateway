"""Verifier-only startup configuration, with an explicit legacy deadline."""
import base64
from datetime import UTC, datetime
import os


def validate_verifier():
    if os.environ.get("HYPERMESH_TICKET_ED25519_PRIVATE_KEY") or os.environ.get("HYPERMESH_TICKET_ED25519_PRIVATE_KEY_FILE") or os.environ.get("HYPERMESH_DEV"):
        raise ValueError("Gateway must not hold a ticket signing key or development fallback")
    public = os.environ.get("HYPERMESH_TICKET_ED25519_PUBLIC_KEY", "")
    if public:
        try:
            if len(base64.b64decode(public, validate=True)) != 32: raise ValueError()
        except ValueError:
            raise ValueError("Invalid ticket verification public key") from None
    legacy = os.environ.get("HYPERMESH_TICKET_HMAC_KEY", "")
    if legacy:
        try:
            deadline = datetime.fromisoformat(os.environ.get("HYPERMESH_TICKET_HMAC_ACCEPT_UNTIL", "").replace("Z", "+00:00"))
            if deadline.tzinfo is None or deadline <= datetime.now(UTC): raise ValueError()
        except ValueError:
            # An expired legacy secret cannot prevent the public-key path serving.
            if not public: raise ValueError("Legacy ticket verification requires an unexpired overlap") from None
    if not public and not legacy:
        raise ValueError("Ticket verification public key is required")
