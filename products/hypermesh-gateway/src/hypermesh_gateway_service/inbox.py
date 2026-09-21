"""AIuditor approval inbox hop from the IR door.

Unset AIUDITOR_SERVICE_URL keeps today's receipt-only hold. The HMAC ticket
and prompt body stay on this door. The plane stores redacted metadata only.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

import httpx

INBOX_UNAVAILABLE = "AIuditor approval inbox hop failed"
INBOX_REQUIRED = "AIUDITOR_SERVICE_URL is required to file a hold"


class InboxUnavailable(Exception):
    """Inbox hop failed. The door must not proxy."""


@dataclass(frozen=True)
class InboxView:
    """Lock fields only. No prompt body."""

    id: uuid.UUID
    status: str
    decision: str | None = None
    consumed: bool = False
    resolved_by: str | None = None
    lease_id: uuid.UUID | None = None
    who: str = ""
    prompt_class: str | None = None
    expires_at: datetime | None = None


class ApprovalInbox(Protocol):
    async def hold(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
        purpose: str = "ir",
    ) -> InboxView | None: ...

    async def latest(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
    ) -> InboxView | None: ...

    async def consume(
        self, tenant_id: uuid.UUID, approval_id: uuid.UUID
    ) -> InboxView: ...


class ClosedApprovalInbox:
    """Fail open when the plane hop is not configured. Receipt-only hold."""

    async def hold(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
        purpose: str = "ir",
    ) -> InboxView | None:
        return None

    async def latest(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
    ) -> InboxView | None:
        return None

    async def consume(
        self, tenant_id: uuid.UUID, approval_id: uuid.UUID
    ) -> InboxView:
        raise InboxUnavailable(INBOX_REQUIRED)


class HttpApprovalInbox:
    """POST/GET /api/v1/aiuditor/approvals with the door internal token."""

    def __init__(
        self, base_url: str, token: str, *, timeout_s: float = 10.0
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout_s

    def _headers(self, tenant_id: uuid.UUID) -> dict[str, str]:
        return {
            "X-Tenant-ID": str(tenant_id),
            "X-Internal-Token": self._token,
        }

    async def hold(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
        purpose: str = "ir",
    ) -> InboxView | None:
        payload: dict[str, object] = {
            "lease_id": str(lease_id),
            "who": who,
            "why": "completion",
            "purpose": purpose,
        }
        if prompt_class:
            payload["prompt_class"] = prompt_class
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base}/api/v1/aiuditor/approvals",
                    headers=self._headers(tenant_id),
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
        if response.status_code >= 400:
            raise InboxUnavailable(INBOX_UNAVAILABLE)
        return _view_from_body(response.json())

    async def latest(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
    ) -> InboxView | None:
        params: dict[str, str] = {"lease_id": str(lease_id), "who": who}
        if prompt_class:
            params["prompt_class"] = prompt_class
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    f"{self._base}/api/v1/aiuditor/approvals/latest",
                    headers=self._headers(tenant_id),
                    params=params,
                )
        except httpx.HTTPError as exc:
            raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise InboxUnavailable(INBOX_UNAVAILABLE)
        return _view_from_body(response.json())

    async def consume(
        self, tenant_id: uuid.UUID, approval_id: uuid.UUID
    ) -> InboxView:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base}/api/v1/aiuditor/approvals/{approval_id}/consume",
                    headers=self._headers(tenant_id),
                )
        except httpx.HTTPError as exc:
            raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
        if response.status_code >= 400:
            raise InboxUnavailable(INBOX_UNAVAILABLE)
        return _view_from_body(response.json())


def _view_from_body(body: object) -> InboxView:
    if not isinstance(body, dict):
        raise InboxUnavailable(INBOX_UNAVAILABLE)
    try:
        raw_id = uuid.UUID(str(body["id"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
    raw_lease = body.get("lease_id")
    raw_exp = body.get("expires_at")
    try:
        lease_id = uuid.UUID(str(raw_lease)) if raw_lease else None
    except (ValueError, TypeError) as exc:
        raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
    expires_at = None
    if raw_exp:
        try:
            expires_at = datetime.fromisoformat(str(raw_exp).replace("Z", "+00:00"))
        except ValueError as exc:
            raise InboxUnavailable(INBOX_UNAVAILABLE) from exc
    return InboxView(
        id=raw_id,
        status=str(body.get("status") or ""),
        decision=str(body["decision"]) if body.get("decision") else None,
        consumed=body.get("consumed_at") is not None,
        resolved_by=str(body["resolved_by"]) if body.get("resolved_by") else None,
        lease_id=lease_id,
        who=str(body.get("who") or ""),
        prompt_class=str(body["prompt_class"]) if body.get("prompt_class") else None,
        expires_at=expires_at,
    )


@dataclass
class FakeApprovalInbox:
    """In-process inbox for door tests. Not the AIuditor store."""

    rows: list[InboxView] = field(default_factory=list)
    hold_calls: list[dict[str, object]] = field(default_factory=list)
    consume_calls: list[uuid.UUID] = field(default_factory=list)
    hold_error: str | None = None
    latest_error: str | None = None
    consume_error: str | None = None

    def seed(self, view: InboxView) -> InboxView:
        self.rows.append(view)
        return view

    async def hold(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
        purpose: str = "ir",
    ) -> InboxView | None:
        del tenant_id
        self.hold_calls.append(
            {
                "lease_id": lease_id,
                "who": who,
                "prompt_class": prompt_class,
                "purpose": purpose,
            }
        )
        if self.hold_error:
            raise InboxUnavailable(self.hold_error)
        existing = await self.latest(
            uuid.UUID(int=0),
            lease_id=lease_id,
            who=who,
            prompt_class=prompt_class,
        )
        if existing is not None and existing.status == "held":
            return existing
        view = InboxView(
            id=uuid.uuid4(),
            status="held",
            lease_id=lease_id,
            who=who,
            prompt_class=prompt_class,
        )
        self.rows.append(view)
        return view

    async def latest(
        self,
        tenant_id: uuid.UUID,
        *,
        lease_id: uuid.UUID,
        who: str,
        prompt_class: str | None,
    ) -> InboxView | None:
        del tenant_id
        if self.latest_error:
            raise InboxUnavailable(self.latest_error)
        matches = [
            row
            for row in self.rows
            if row.lease_id == lease_id and row.who == who
        ]
        exact = [row for row in matches if row.prompt_class == prompt_class]
        sessions = [
            row
            for row in matches
            if row.status == "allowed" and row.decision == "allow_session"
        ]
        if exact:
            newest = exact[-1]
            if newest.status == "allowed" and newest.decision == "allow_once" and newest.consumed and sessions:
                return sessions[-1]
            return newest
        if sessions:
            return sessions[-1]
        return None

    async def consume(
        self, tenant_id: uuid.UUID, approval_id: uuid.UUID
    ) -> InboxView:
        del tenant_id
        self.consume_calls.append(approval_id)
        if self.consume_error:
            raise InboxUnavailable(self.consume_error)
        for index, row in enumerate(self.rows):
            if row.id == approval_id:
                updated = InboxView(
                    id=row.id,
                    status=row.status,
                    decision=row.decision,
                    consumed=True,
                    resolved_by=row.resolved_by,
                    lease_id=row.lease_id,
                    who=row.who,
                    prompt_class=row.prompt_class,
                    expires_at=row.expires_at,
                )
                self.rows[index] = updated
                return updated
        raise InboxUnavailable(INBOX_UNAVAILABLE)


def resolve_approval_inbox(
    inbox: ApprovalInbox | None = None,
) -> ApprovalInbox:
    if inbox is not None:
        return inbox
    url = (os.environ.get("AIUDITOR_SERVICE_URL") or "").strip()
    token = (os.environ.get("AIUDITOR_INTERNAL_TOKEN") or "").strip()
    if not url or not token:
        return ClosedApprovalInbox()
    return HttpApprovalInbox(url, token)
