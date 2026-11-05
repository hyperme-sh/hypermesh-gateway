"""Router prompt verbs. The UI calls this door; the host is not commanded.

Auth is the renter chat grant: a portal JWT or a renter API key, plus a
paid active ticket for purpose ``renter`` or ``service``. There is no
second identity. ``hm_gw_``, ``hm_dev_`` and ``hm_site_`` stay rejected.

The router applies what it can on this process and says so. Recipient
acknowledgement is a separate hop and is not delivered here. State is
local to this process: a restart drops it, and another replica does not
see it. Verbs that need a catalog, a policy gate, or a host command the
router does not have return ``not_wired`` and change nothing.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hypermesh_gateway_service.chat import ChatCompletionRequest
from hypermesh_gateway_service.errors import (
    LEASE_NOT_OWNED_MESSAGE,
    DoorError,
    instance_not_ready,
    model_not_found_message,
    no_active_lease_message,
)
from hypermesh_gateway_service.posture import require_chat_posture
from hypermesh_gateway_service.route_resolve import (
    KeyPolicy,
    LeaseNotOwned,
    ModelNotFound,
    TenantOwnedKeyPolicy,
    catalog_ids,
    resolve_route,
    select_lease,
)
from hypermesh_gateway_service.tickets import CachedTicket, TicketCache
from hypermesh_ticket import RENTER_CHAT_PURPOSES, TicketNotReady, require_renter_chat_purpose

logger = logging.getLogger(__name__)

MAX_APPENDS = 8
MAX_APPEND_CHARS = 4_096
MAX_STYLE_CHARS = 512
MAX_ATTACHMENTS = 8
MAX_ATTACHMENT_CHARS = 16_384
MAX_NAME_CHARS = 128
MAX_GOAL_CHARS = 1_024
MAX_RESULT_CHARS = 4_096
MAX_THOUGHTS = 16
MAX_THOUGHT_CHARS = 2_048
MAX_FRAMES = 8
MAX_COMPLETED = 16
MAX_INJECTED_CHARS = 64 * 1024
MAX_CACHE_ENTRIES = 64
MAX_CACHE_CHARS = 32_768
MAX_CACHE_TTL_S = 86_400
DEFAULT_CACHE_TTL_S = 3_600
MAX_AUDIT = 100
MAX_AUDIT_REASON = 512
_CACHE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

RUN_PAUSED = "Router paused this lease. New completions are not forwarded."
RUN_DRAINING = "Router is draining this lease. New completions are not forwarded."
RUN_CANCELLED = "Router cancelled this lease. New completions are not forwarded."


class VerbError(Exception):
    def __init__(self, http_status: int, status: str, detail: str, **extra: Any) -> None:
        super().__init__(detail)
        self.http_status = http_status
        self.status = status
        self.detail = detail
        self.extra = extra


class HostExcluded(Exception):
    """An explicit lease points at a device the caller told the router to drop."""

    def __init__(self, lease_id: uuid.UUID, device_id: str) -> None:
        super().__init__(device_id)
        self.lease_id = lease_id
        self.device_id = device_id


@dataclass(frozen=True)
class VerbSpec:
    verb: str
    family: str
    wired: bool
    summary: str


VERB_SPECS: tuple[VerbSpec, ...] = (
    VerbSpec("pause", "run_control", True, "Refuse new completions for this lease until resume. Does not command the host. State is local to this gateway process."),
    VerbSpec("resume", "run_control", True, "Accept new completions for this lease again. Does not command the host."),
    VerbSpec("drain", "run_control", True, "Refuse new completions. A completion already handed to the host is not revoked."),
    VerbSpec("cancel", "run_control", True, "Refuse new completions. A completion already handed to the host is not revoked."),
    VerbSpec("use_model", "model_mix", True, "Pin a catalog id for later completions from this caller that omit model. An explicit model on a completion still wins."),
    VerbSpec("mix_models", "model_mix", False, "Not wired. The router cannot blend models and did not store a mix or change routing."),
    VerbSpec("prefer_tier", "model_mix", False, "Not wired. Tickets have no tier. The router did not store a preference."),
    VerbSpec("route_hint", "routing", False, "Not wired. A free-form hint is not applied. The router did not store it or change lease choice."),
    VerbSpec("prefer_host", "routing", True, "Prefer one host device id when a completion omits lease_id. Falls through when that host cannot serve the requested model."),
    VerbSpec("exclude_host", "routing", True, "Drop a host device id from lease choice. An explicit lease on that host is refused."),
    VerbSpec("affinity", "routing", True, "Stick later completions that omit lease_id to one lease until that lease cannot serve the request."),
    VerbSpec("system_append", "prompt", True, "Append a system message on later completions for this caller."),
    VerbSpec("style", "prompt", True, "Add a Style system message on later completions for this caller."),
    VerbSpec("temperature_hint", "prompt", True, "Set temperature on a later completion only when that completion omits temperature."),
    VerbSpec("safety_context", "safety", False, "Not wired. The router does not store safety context and does not change allow, hold, or deny."),
    VerbSpec("op_class", "safety", False, "Not wired. The router does not store an op class and does not change allow, hold, or deny."),
    VerbSpec("audit_override_request", "audit", True, "Log a request to pass a gate, then deny it. Nothing is bypassed."),
    VerbSpec("attach", "attachments", True, "Bind inline text into later completions for this caller. The router does not fetch a uri."),
    VerbSpec("detach", "attachments", True, "Remove one attached artifact from later completions."),
    VerbSpec("list_attachments", "attachments", True, "List artifacts attached for this caller."),
    VerbSpec("share", "share_cache", True, "Mark one of this caller's cache entries readable by other subjects in the tenant. Process-local."),
    VerbSpec("unshare", "share_cache", True, "Make a shared cache entry private to its owner again."),
    VerbSpec("cache_put", "share_cache", True, "Store a process-local value for this tenant. A restart drops it. It is not shared until share."),
    VerbSpec("cache_get", "share_cache", True, "Read a process-local cache value this caller owns or that was shared in the tenant."),
    VerbSpec("frame_push", "stack_frames", True, "Push a named frame onto the router preamble sent with later completions. The caller transcript is not rewritten."),
    VerbSpec("frame_next", "stack_frames", True, "Keep the current frame result, drop that frame from the preamble, and push the next frame."),
    VerbSpec("frame_pop", "stack_frames", True, "Drop the current frame from the preamble and keep its result. The caller transcript is left as sent."),
    VerbSpec("think", "stack_frames", True, "Store a named fact that stays in the preamble after frames pop."),
    VerbSpec("skill_load", "skills", False, "Not wired. This gateway has no skill catalog and did not load a pack."),
    VerbSpec("skill_unload", "skills", False, "Not wired. This gateway has no skill catalog and did not unload a pack."),
    VerbSpec("skill_list", "skills", False, "Not wired. This gateway has no skill catalog. An empty list is not a loaded pack set."),
)

_SPECS = {spec.verb: spec for spec in VERB_SPECS}


@dataclass
class _Frame:
    name: str
    goal: str


@dataclass
class _Done:
    name: str
    result: str


@dataclass
class _Attachment:
    attachment_id: str
    name: str
    media_type: str
    text: str


@dataclass
class CallerSession:
    model_pin: str | None = None
    prefer_host: str | None = None
    exclude_hosts: set[str] = field(default_factory=set)
    affinity: uuid.UUID | None = None
    system_append: list[str] = field(default_factory=list)
    style: str | None = None
    temperature_hint: float | None = None
    attachments: OrderedDict[str, _Attachment] = field(default_factory=OrderedDict)
    frames: list[_Frame] = field(default_factory=list)
    completed: list[_Done] = field(default_factory=list)
    thoughts: OrderedDict[str, str] = field(default_factory=OrderedDict)

    def has_routing(self) -> bool:
        return bool(self.exclude_hosts or self.prefer_host or self.affinity is not None)

    def affects_prompt(self) -> bool:
        return bool(
            self.system_append
            or self.style
            or self.temperature_hint is not None
            or self.attachments
            or self.frames
            or self.completed
            or self.thoughts
        )


@dataclass
class _CacheEntry:
    owner: str
    text: str
    shared: bool
    expires_at: float


@dataclass(frozen=True)
class AuditOverride:
    command_id: str
    tenant_id: str
    lease_id: str
    subject: str
    reason: str
    decision: str
    recorded_at: str


class RouterVerbStore:
    """Process-local router policy. Not durable and not replicated."""

    def __init__(self, *, clock=None) -> None:
        self._clock = clock or time.monotonic
        self._runs: dict[tuple[uuid.UUID, uuid.UUID], str] = {}
        self._callers: dict[tuple[uuid.UUID, str], CallerSession] = {}
        self._cache: dict[uuid.UUID, OrderedDict[str, _CacheEntry]] = {}
        self._audit: dict[uuid.UUID, list[AuditOverride]] = {}

    def now(self) -> float:
        return float(self._clock())

    def run_state(self, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> str:
        return self._runs.get((tenant_id, lease_id), "running")

    def set_run(self, tenant_id: uuid.UUID, lease_id: uuid.UUID, state: str) -> str:
        self._runs[(tenant_id, lease_id)] = state
        return state

    def caller(self, tenant_id: uuid.UUID, subject: str) -> CallerSession:
        key = (tenant_id, subject)
        session = self._callers.get(key)
        if session is None:
            session = CallerSession()
            self._callers[key] = session
        return session

    def caller_existing(self, tenant_id: uuid.UUID, subject: str) -> CallerSession | None:
        return self._callers.get((tenant_id, subject))

    def record_audit(self, record: AuditOverride) -> None:
        tenant_id = uuid.UUID(record.tenant_id)
        rows = self._audit.setdefault(tenant_id, [])
        rows.append(record)
        if len(rows) > MAX_AUDIT:
            del rows[: len(rows) - MAX_AUDIT]

    def audit_for(self, tenant_id: uuid.UUID) -> list[AuditOverride]:
        return list(self._audit.get(tenant_id, ()))

    def cache_put(
        self,
        tenant_id: uuid.UUID,
        subject: str,
        key: str,
        text: str,
        ttl_s: float,
    ) -> None:
        table = self._cache.setdefault(tenant_id, OrderedDict())
        self._purge_cache(tenant_id)
        current = table.get(key)
        if current is not None and current.owner != subject:
            raise VerbError(403, "rejected", "Only the owner can replace this cache entry.")
        if current is None and len(table) >= MAX_CACHE_ENTRIES:
            raise VerbError(409, "rejected", "The process-local cache for this tenant is full.")
        table[key] = _CacheEntry(
            owner=subject,
            text=text,
            shared=False,
            expires_at=self.now() + ttl_s,
        )
        table.move_to_end(key)

    def cache_get(self, tenant_id: uuid.UUID, subject: str, key: str) -> str:
        self._purge_cache(tenant_id)
        entry = self._cache.get(tenant_id, {}).get(key)
        if entry is None or (entry.owner != subject and not entry.shared):
            raise VerbError(404, "miss", "No cache entry by that key is visible to this caller.")
        return entry.text

    def share_cache(self, tenant_id: uuid.UUID, subject: str, key: str, *, shared: bool) -> None:
        self._purge_cache(tenant_id)
        entry = self._cache.get(tenant_id, {}).get(key)
        if entry is None:
            raise VerbError(404, "miss", "No cache entry by that key.")
        if entry.owner != subject:
            raise VerbError(403, "rejected", "Only the owner can change sharing for this cache entry.")
        entry.shared = shared

    def visible_cache_keys(self, tenant_id: uuid.UUID, subject: str) -> list[str]:
        self._purge_cache(tenant_id)
        table = self._cache.get(tenant_id, {})
        return sorted(
            key for key, entry in table.items() if entry.owner == subject or entry.shared
        )

    def _purge_cache(self, tenant_id: uuid.UUID) -> None:
        table = self._cache.get(tenant_id)
        if not table:
            return
        now = self.now()
        stale = [key for key, entry in table.items() if entry.expires_at <= now]
        for key in stale:
            del table[key]


def verb_store(request: Request) -> RouterVerbStore:
    store = getattr(request.app.state, "verb_store", None)
    if store is None:
        store = RouterVerbStore()
        request.app.state.verb_store = store
    return store


def _device_key(ticket: CachedTicket) -> str:
    if ticket.device_id is None:
        return ""
    return str(ticket.device_id)


def resolve_for_caller(
    store: RouterVerbStore,
    cache: TicketCache,
    *,
    key: str | None,
    tenant_id: uuid.UUID,
    subject: str,
    requested_model: str | None,
    requested_lease_id: uuid.UUID | None,
    purposes: frozenset[str],
    policy: KeyPolicy | None = None,
) -> CachedTicket | None:
    """Lease choice for chat and verbs.

    With no pin and no routing prefs this is ``resolve_route``. A pin fills
    an omitted model. Exclude drops devices. Prefer and affinity apply only
    when the completion does not name a lease, and they fall through when
    they cannot serve the model.
    """

    session = store.caller_existing(tenant_id, subject)
    model = (requested_model or "").strip()
    if not model and session is not None and session.model_pin:
        model = session.model_pin
    chosen = policy or TenantOwnedKeyPolicy()
    passed_model = model or None
    if requested_lease_id is not None:
        lease = resolve_route(
            cache,
            key=key,
            tenant_id=tenant_id,
            requested_model=passed_model,
            requested_lease_id=requested_lease_id,
            purposes=purposes,
            policy=chosen,
        )
        if (
            lease is not None
            and session is not None
            and _device_key(lease)
            and _device_key(lease) in session.exclude_hosts
        ):
            raise HostExcluded(lease.lease_id, _device_key(lease))
        return lease
    if session is None or not session.has_routing():
        return resolve_route(
            cache,
            key=key,
            tenant_id=tenant_id,
            requested_model=passed_model,
            requested_lease_id=None,
            purposes=purposes,
            policy=chosen,
        )
    candidates = chosen.candidate_leases(cache, tenant_id, key=key, purposes=purposes)
    candidates = [
        ticket
        for ticket in candidates
        if not _device_key(ticket) or _device_key(ticket) not in session.exclude_hosts
    ]
    if not candidates:
        if passed_model:
            raise ModelNotFound(passed_model, [])
        return None
    if session.affinity is not None:
        sticky = [ticket for ticket in candidates if ticket.lease_id == session.affinity]
        if sticky:
            try:
                return select_lease(sticky, passed_model)
            except ModelNotFound:
                pass
    if session.prefer_host:
        preferred = [
            ticket for ticket in candidates if _device_key(ticket) == session.prefer_host
        ]
        if preferred:
            try:
                return select_lease(preferred, passed_model)
            except ModelNotFound:
                pass
    return select_lease(candidates, passed_model)


def gate_new_work(store: RouterVerbStore, tenant_id: uuid.UUID, lease_id: uuid.UUID) -> None:
    """Refuse a new completion. Does not touch a stream already handed to the host."""

    state = store.run_state(tenant_id, lease_id)
    if state == "running":
        return
    if state == "paused":
        raise DoorError(409, RUN_PAUSED, "run_paused")
    if state == "draining":
        raise DoorError(409, RUN_DRAINING, "run_draining")
    if state == "cancelled":
        raise DoorError(409, RUN_CANCELLED, "run_cancelled")
    raise DoorError(409, "Router refused new completions for this lease.", "run_refused")


def _render_preamble(session: CallerSession) -> str | None:
    parts: list[str] = []
    if session.thoughts:
        lines = "\n".join(f"- {name}: {text}" for name, text in session.thoughts.items())
        parts.append("Thoughts:\n" + lines)
    if session.completed:
        lines = "\n".join(f"- {item.name}: {item.result}" for item in session.completed)
        parts.append("Completed frame results:\n" + lines)
    if session.frames:
        lines = "\n".join(
            f"- {item.name}: {item.goal}" if item.goal else f"- {item.name}"
            for item in session.frames
        )
        parts.append("Active frames:\n" + lines)
    if not parts:
        return None
    return "Hypermesh router frames\n\n" + "\n\n".join(parts)


def prepare_chat_payload(
    store: RouterVerbStore,
    tenant_id: uuid.UUID,
    subject: str,
    body: ChatCompletionRequest,
) -> dict[str, Any] | None:
    """Return the payload to forward, or None when the router adds nothing.

    Injected system messages are prepended. The caller's own messages stay
    in the order they were sent. Pop drops router frame text from this
    preamble only.
    """

    session = store.caller_existing(tenant_id, subject)
    if session is None or not session.affects_prompt():
        return None
    payload = body.model_dump(mode="json")
    inserts: list[dict[str, str]] = [
        {"role": "system", "content": text} for text in session.system_append
    ]
    if session.style:
        inserts.append({"role": "system", "content": f"Style: {session.style}"})
    if session.attachments:
        blocks = [
            f"## {item.name}\n{item.text}" for item in session.attachments.values()
        ]
        inserts.append(
            {"role": "system", "content": "Attached artifacts:\n\n" + "\n\n".join(blocks)}
        )
    preamble = _render_preamble(session)
    if preamble is not None:
        inserts.append({"role": "system", "content": preamble})
    messages = list(payload.get("messages") or [])
    payload["messages"] = inserts + messages
    if session.temperature_hint is not None and "temperature" not in payload:
        payload["temperature"] = session.temperature_hint
    return payload


def _plain(value: str, *, max_len: int, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise VerbError(400, "invalid_args", f"{label} must be a string.")
    text = value.strip()
    if (not text and not allow_empty) or len(text) > max_len:
        raise VerbError(400, "invalid_args", f"{label} must be 1..{max_len} characters.")
    if any(ord(char) < 32 for char in text):
        raise VerbError(400, "invalid_args", f"{label} must not contain control characters.")
    return text


def _body_text(value: str, *, max_len: int, label: str) -> str:
    if not isinstance(value, str):
        raise VerbError(400, "invalid_args", f"{label} must be a string.")
    if not value or len(value) > max_len:
        raise VerbError(400, "invalid_args", f"{label} must be 1..{max_len} characters.")
    if "\x00" in value:
        raise VerbError(400, "invalid_args", f"{label} must not contain NUL.")
    return value


def _parse(model: type[BaseModel], args: dict[str, Any]) -> Any:
    try:
        return model.model_validate(args)
    except ValidationError as exc:
        raise VerbError(400, "invalid_args", "Invalid arguments for this verb.") from exc


def _injected_size(session: CallerSession) -> int:
    payload = 0
    payload += sum(len(text) for text in session.system_append)
    if session.style:
        payload += len(session.style) + len("Style: ")
    for item in session.attachments.values():
        payload += len(item.name) + len(item.text)
    for item in session.frames:
        payload += len(item.name) + len(item.goal)
    for item in session.completed:
        payload += len(item.name) + len(item.result)
    for name, text in session.thoughts.items():
        payload += len(name) + len(text)
    return payload


def _require_room(session: CallerSession) -> None:
    if _injected_size(session) > MAX_INJECTED_CHARS:
        raise VerbError(
            400,
            "invalid_args",
            "Router context for this caller is over the size limit.",
        )


class _Empty(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _UseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str | None = None
    clear: bool = False


class _MixItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=128)
    weight: float = Field(gt=0, le=100)


class _MixModels(BaseModel):
    model_config = ConfigDict(extra="forbid")
    models: list[_MixItem] = Field(min_length=2, max_length=4)


class _Tier(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tier: str = Field(min_length=1, max_length=64)


class _Hint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hint: str = Field(min_length=1, max_length=256)


class _Host(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str | None = None
    clear: bool = False
    remove: bool = False


class _Affinity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_id: uuid.UUID | None = None
    clear: bool = False


class _Append(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str | None = None
    clear: bool = False


class _Style(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str | None = None
    clear: bool = False


class _Temperature(BaseModel):
    model_config = ConfigDict(extra="forbid")
    temperature: float | None = None
    clear: bool = False


class _Note(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=512)


class _OpClass(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op_class: str = Field(min_length=1, max_length=64)


class _Audit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str


class _Attach(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    text: str
    media_type: str = "text/plain"


class _Detach(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attachment_id: str


class _CachePut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    text: str
    ttl_s: float = DEFAULT_CACHE_TTL_S


class _CacheKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str


class _FramePush(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    goal: str = ""


class _FrameNext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result: str
    name: str
    goal: str = ""


class _FramePop(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result: str = ""


class _Think(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    text: str | None = None
    clear: bool = False


class _SkillName(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)


def _device_arg(raw: str | None) -> str:
    if raw is None:
        raise VerbError(400, "invalid_args", "device_id is required.")
    try:
        return str(uuid.UUID(str(raw)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise VerbError(400, "invalid_args", "device_id must be a UUID.") from exc


def _cache_key(raw: str) -> str:
    if not isinstance(raw, str) or not _CACHE_KEY.fullmatch(raw):
        raise VerbError(
            400,
            "invalid_args",
            "key must be 1..128 characters of letters, digits, and . _ : -",
        )
    return raw


def _transition(state: str, verb: str) -> str:
    if verb == "pause":
        if state == "cancelled":
            raise VerbError(
                409,
                "rejected",
                "Resume the lease before pausing it.",
                run=state,
            )
        return "paused"
    if verb == "resume":
        return "running"
    if verb == "drain":
        if state == "cancelled":
            raise VerbError(
                409,
                "rejected",
                "A cancelled lease does not drain. Resume it to accept work.",
                run=state,
            )
        return "draining"
    if verb == "cancel":
        return "cancelled"
    raise VerbError(400, "invalid_args", "Unknown run-control verb.")


def _run_detail(state: str) -> str:
    if state == "paused":
        return (
            "Router will refuse new completions for this lease. "
            "The host was not commanded. Recipient acknowledgement was not delivered."
        )
    if state == "draining":
        return (
            "Router will refuse new completions for this lease. "
            "A completion already handed to the host is not revoked. "
            "Recipient acknowledgement was not delivered."
        )
    if state == "cancelled":
        return (
            "Router will refuse new completions for this lease. "
            "A completion already handed to the host is not revoked. "
            "Recipient acknowledgement was not delivered."
        )
    return (
        "Router will forward new completions for this lease. "
        "The host was not commanded. Recipient acknowledgement was not delivered."
    )


def _attachment_view(item: _Attachment, *, include_text: bool) -> dict[str, Any]:
    view: dict[str, Any] = {
        "attachment_id": item.attachment_id,
        "name": item.name,
        "media_type": item.media_type,
        "bytes": len(item.text.encode("utf-8")),
    }
    if include_text:
        view["text"] = item.text
    return view


def _apply(
    spec: VerbSpec,
    store: RouterVerbStore,
    *,
    tenant_id: uuid.UUID,
    subject: str,
    lease_id: uuid.UUID,
    cache: TicketCache,
    args: dict[str, Any],
    command_id: str,
) -> dict[str, Any]:
    session = store.caller(tenant_id, subject)
    if spec.verb in {"pause", "resume", "drain", "cancel"}:
        _parse(_Empty, args)
        state = _transition(store.run_state(tenant_id, lease_id), spec.verb)
        store.set_run(tenant_id, lease_id, state)
        return {
            "status": "accepted",
            "wired": True,
            "recipient_ack": "not_delivered",
            "run": state,
            "detail": _run_detail(state),
        }
    if spec.verb == "use_model":
        parsed = _parse(_UseModel, args)
        if parsed.clear and parsed.model:
            raise VerbError(400, "invalid_args", "use_model takes a model or clear, not both.")
        if not parsed.clear and not parsed.model:
            raise VerbError(400, "invalid_args", "use_model takes a model or clear.")
        if parsed.clear:
            session.model_pin = None
            return _accepted("Cleared the model pin for this caller.")
        model = _plain(parsed.model or "", max_len=128, label="model")
        available = catalog_ids(
            cache.honoring_leases(tenant_id, purposes=RENTER_CHAT_PURPOSES)
        )
        if model not in available:
            raise DoorError(404, model_not_found_message(model, available), "model_not_found")
        session.model_pin = model
        return _accepted("Pinned this catalog id for completions that omit model.", model=model)
    if spec.verb == "prefer_host":
        parsed = _parse(_Host, args)
        if parsed.remove:
            raise VerbError(400, "invalid_args", "prefer_host does not take remove. Use clear.")
        if parsed.clear and parsed.device_id:
            raise VerbError(400, "invalid_args", "prefer_host takes a device_id or clear, not both.")
        if parsed.clear:
            session.prefer_host = None
            return _accepted("Cleared the preferred host.")
        session.prefer_host = _device_arg(parsed.device_id)
        return _accepted(
            "Later completions that omit lease_id prefer this device when it can serve the model.",
            device_id=session.prefer_host,
        )
    if spec.verb == "exclude_host":
        parsed = _parse(_Host, args)
        if parsed.clear and (parsed.device_id or parsed.remove):
            raise VerbError(400, "invalid_args", "exclude_host clear cannot be combined with a device.")
        if parsed.clear:
            session.exclude_hosts.clear()
            return _accepted("Cleared excluded hosts.")
        device_id = _device_arg(parsed.device_id)
        if parsed.remove:
            session.exclude_hosts.discard(device_id)
            return _accepted("Removed that device from the exclude set.", device_id=device_id)
        session.exclude_hosts.add(device_id)
        return _accepted(
            "Later lease choice drops this device. An explicit lease on it is refused.",
            device_id=device_id,
        )
    if spec.verb == "affinity":
        parsed = _parse(_Affinity, args)
        if parsed.clear and parsed.lease_id is not None:
            raise VerbError(400, "invalid_args", "affinity takes a lease_id or clear, not both.")
        if parsed.clear:
            session.affinity = None
            return _accepted("Cleared lease affinity.")
        if parsed.lease_id is None:
            raise VerbError(400, "invalid_args", "affinity takes a lease_id or clear.")
        if cache.get(tenant_id, parsed.lease_id) is None:
            raise DoorError(403, LEASE_NOT_OWNED_MESSAGE, "lease_not_owned")
        session.affinity = parsed.lease_id
        return _accepted(
            "Later completions that omit lease_id stick to this lease while it can serve them.",
            affinity=str(parsed.lease_id),
        )
    if spec.verb == "system_append":
        parsed = _parse(_Append, args)
        if parsed.clear:
            session.system_append.clear()
            return _accepted("Cleared appended system text.")
        text = _body_text(parsed.text or "", max_len=MAX_APPEND_CHARS, label="text")
        if len(session.system_append) >= MAX_APPENDS:
            raise VerbError(400, "invalid_args", f"At most {MAX_APPENDS} system appends.")
        session.system_append.append(text)
        try:
            _require_room(session)
        except VerbError:
            session.system_append.pop()
            raise
        return _accepted("Appended system text for later completions from this caller.")
    if spec.verb == "style":
        parsed = _parse(_Style, args)
        if parsed.clear:
            session.style = None
            return _accepted("Cleared style.")
        previous = session.style
        session.style = _plain(parsed.text or "", max_len=MAX_STYLE_CHARS, label="text")
        try:
            _require_room(session)
        except VerbError:
            session.style = previous
            raise
        return _accepted("Later completions from this caller include this style line.")
    if spec.verb == "temperature_hint":
        parsed = _parse(_Temperature, args)
        if parsed.clear:
            session.temperature_hint = None
            return _accepted("Cleared the temperature hint.")
        if parsed.temperature is None or not (0.0 <= parsed.temperature <= 2.0):
            raise VerbError(400, "invalid_args", "temperature must be between 0 and 2.")
        session.temperature_hint = float(parsed.temperature)
        return _accepted(
            "Applied when a later completion omits temperature. An explicit temperature wins.",
            temperature_hint=session.temperature_hint,
        )
    if spec.verb == "audit_override_request":
        parsed = _parse(_Audit, args)
        reason = _body_text(parsed.reason, max_len=MAX_AUDIT_REASON, label="reason")
        store.record_audit(
            AuditOverride(
                command_id=command_id,
                tenant_id=str(tenant_id),
                lease_id=str(lease_id),
                subject=subject,
                reason=reason,
                decision="denied",
                recorded_at=datetime.now(UTC).isoformat(),
            )
        )
        raise VerbError(
            403,
            "denied",
            "Override request logged and denied. This router has no path that bypasses a gate.",
            decision="denied",
        )
    if spec.verb == "attach":
        if "uri" in args or "url" in args:
            raise VerbError(
                400,
                "invalid_args",
                "attach accepts inline text. The router does not fetch a uri.",
            )
        parsed = _parse(_Attach, args)
        if len(session.attachments) >= MAX_ATTACHMENTS:
            raise VerbError(400, "invalid_args", f"At most {MAX_ATTACHMENTS} attachments.")
        name = _plain(parsed.name, max_len=MAX_NAME_CHARS, label="name")
        media = _plain(parsed.media_type, max_len=MAX_NAME_CHARS, label="media_type")
        text = _body_text(parsed.text, max_len=MAX_ATTACHMENT_CHARS, label="text")
        item = _Attachment(
            attachment_id=str(uuid.uuid4()),
            name=name,
            media_type=media,
            text=text,
        )
        session.attachments[item.attachment_id] = item
        try:
            _require_room(session)
        except VerbError:
            del session.attachments[item.attachment_id]
            raise
        return _accepted(
            "Attached inline text for later completions. The bytes were not fetched.",
            attachment=_attachment_view(item, include_text=False),
        )
    if spec.verb == "detach":
        parsed = _parse(_Detach, args)
        item = session.attachments.pop(parsed.attachment_id, None)
        if item is None:
            raise VerbError(404, "miss", "No attachment with that id.")
        return _accepted("Removed the attachment.", attachment_id=item.attachment_id)
    if spec.verb == "list_attachments":
        _parse(_Empty, args)
        return _accepted(
            "Inline attachments for this caller.",
            attachments=[
                _attachment_view(item, include_text=True)
                for item in session.attachments.values()
            ],
        )
    if spec.verb == "cache_put":
        parsed = _parse(_CachePut, args)
        if not (1 <= parsed.ttl_s <= MAX_CACHE_TTL_S):
            raise VerbError(
                400,
                "invalid_args",
                f"ttl_s must be between 1 and {MAX_CACHE_TTL_S}.",
            )
        store.cache_put(
            tenant_id,
            subject,
            _cache_key(parsed.key),
            _body_text(parsed.text, max_len=MAX_CACHE_CHARS, label="text"),
            parsed.ttl_s,
        )
        return _accepted(
            "Stored a process-local value. A rewrite is private until share. A restart drops it.",
            key=parsed.key,
        )
    if spec.verb == "cache_get":
        parsed = _parse(_CacheKey, args)
        text = store.cache_get(tenant_id, subject, _cache_key(parsed.key))
        return _accepted("Process-local cache hit.", key=parsed.key, text=text)
    if spec.verb in {"share", "unshare"}:
        parsed = _parse(_CacheKey, args)
        store.share_cache(
            tenant_id,
            subject,
            _cache_key(parsed.key),
            shared=spec.verb == "share",
        )
        if spec.verb == "share":
            return _accepted(
                "Other subjects in this tenant can read this process-local entry.",
                key=parsed.key,
                shared=True,
            )
        return _accepted("The entry is private to its owner again.", key=parsed.key, shared=False)
    if spec.verb == "frame_push":
        parsed = _parse(_FramePush, args)
        if len(session.frames) >= MAX_FRAMES:
            raise VerbError(400, "invalid_args", f"At most {MAX_FRAMES} active frames.")
        frame = _Frame(
            name=_plain(parsed.name, max_len=MAX_NAME_CHARS, label="name"),
            goal=_plain(parsed.goal, max_len=MAX_GOAL_CHARS, label="goal", allow_empty=True)
            if parsed.goal
            else "",
        )
        session.frames.append(frame)
        try:
            _require_room(session)
        except VerbError:
            session.frames.pop()
            raise
        return _accepted(
            "Pushed a frame. Later completions gain it in the router preamble. The caller transcript is unchanged.",
            depth=len(session.frames),
        )
    if spec.verb == "frame_next":
        parsed = _parse(_FrameNext, args)
        if not session.frames:
            raise VerbError(409, "rejected", "There is no active frame.", depth=0)
        result = _body_text(parsed.result, max_len=MAX_RESULT_CHARS, label="result")
        nxt = _Frame(
            name=_plain(parsed.name, max_len=MAX_NAME_CHARS, label="name"),
            goal=_plain(parsed.goal, max_len=MAX_GOAL_CHARS, label="goal", allow_empty=True)
            if parsed.goal
            else "",
        )
        current = session.frames.pop()
        session.completed.append(_Done(name=current.name, result=result))
        trimmed: _Done | None = None
        if len(session.completed) > MAX_COMPLETED:
            trimmed = session.completed.pop(0)
        session.frames.append(nxt)
        try:
            _require_room(session)
        except VerbError:
            session.frames.pop()
            session.frames.append(current)
            session.completed.pop()
            if trimmed is not None:
                session.completed.insert(0, trimmed)
            raise
        return _accepted(
            "Saved the frame result, dropped that frame from the preamble, and pushed the next one.",
            depth=len(session.frames),
        )
    if spec.verb == "frame_pop":
        parsed = _parse(_FramePop, args)
        if not session.frames:
            raise VerbError(409, "rejected", "There is no active frame.", depth=0)
        result = (
            _body_text(parsed.result, max_len=MAX_RESULT_CHARS, label="result")
            if parsed.result
            else ""
        )
        previous_completed = list(session.completed)
        current = session.frames.pop()
        session.completed.append(_Done(name=current.name, result=result))
        if len(session.completed) > MAX_COMPLETED:
            del session.completed[: len(session.completed) - MAX_COMPLETED]
        try:
            _require_room(session)
        except VerbError:
            session.frames.append(current)
            session.completed[:] = previous_completed
            raise
        return _accepted(
            "Dropped the frame from the router preamble and kept its result. Caller messages were not removed.",
            depth=len(session.frames),
        )
    if spec.verb == "think":
        parsed = _parse(_Think, args)
        name = _plain(parsed.name, max_len=MAX_NAME_CHARS, label="name")
        if parsed.clear:
            session.thoughts.pop(name, None)
            return _accepted("Cleared that thought.", name=name)
        if parsed.text is None:
            raise VerbError(400, "invalid_args", "think takes text or clear.")
        text = _body_text(parsed.text, max_len=MAX_THOUGHT_CHARS, label="text")
        if name not in session.thoughts and len(session.thoughts) >= MAX_THOUGHTS:
            raise VerbError(400, "invalid_args", f"At most {MAX_THOUGHTS} thoughts.")
        previous = session.thoughts.get(name)
        session.thoughts[name] = text
        session.thoughts.move_to_end(name)
        try:
            _require_room(session)
        except VerbError:
            if previous is None:
                del session.thoughts[name]
            else:
                session.thoughts[name] = previous
            raise
        return _accepted(
            "Stored a fact that stays in the preamble after frame_pop.",
            name=name,
        )
    if not spec.wired:
        if spec.verb == "mix_models":
            _parse(_MixModels, args)
        elif spec.verb == "prefer_tier":
            _parse(_Tier, args)
        elif spec.verb == "route_hint":
            _parse(_Hint, args)
        elif spec.verb == "safety_context":
            _parse(_Note, args)
        elif spec.verb == "op_class":
            _parse(_OpClass, args)
        elif spec.verb in {"skill_load", "skill_unload"}:
            _parse(_SkillName, args)
        elif spec.verb == "skill_list":
            _parse(_Empty, args)
        extra: dict[str, Any] = {}
        if spec.verb == "skill_list":
            extra["skills"] = []
        return {
            "status": "not_wired",
            "wired": False,
            "recipient_ack": "not_applicable",
            "detail": spec.summary,
            **extra,
        }
    raise VerbError(400, "unknown_verb", "Unknown router verb.")


def _accepted(detail: str, **extra: Any) -> dict[str, Any]:
    return {
        "status": "accepted",
        "wired": True,
        "recipient_ack": "not_delivered",
        "detail": detail,
        **extra,
    }


def _session_view(
    store: RouterVerbStore,
    *,
    tenant_id: uuid.UUID,
    subject: str,
    lease_id: uuid.UUID | None,
) -> dict[str, Any]:
    session = store.caller_existing(tenant_id, subject) or CallerSession()
    return {
        "object": "hypermesh.router_session",
        "lease_id": str(lease_id) if lease_id is not None else None,
        "subject": subject,
        "run": store.run_state(tenant_id, lease_id) if lease_id is not None else None,
        "model_pin": session.model_pin,
        "routing": {
            "prefer_host": session.prefer_host,
            "exclude_hosts": sorted(session.exclude_hosts),
            "affinity": str(session.affinity) if session.affinity else None,
        },
        "prompt": {
            "system_append": list(session.system_append),
            "style": session.style,
            "temperature_hint": session.temperature_hint,
        },
        "attachments": [
            _attachment_view(item, include_text=False) for item in session.attachments.values()
        ],
        "frames": {
            "active": [{"name": item.name, "goal": item.goal} for item in session.frames],
            "completed": [
                {"name": item.name, "result": item.result} for item in session.completed
            ],
            "thoughts": [
                {"name": name, "text": text} for name, text in session.thoughts.items()
            ],
        },
        "cache_keys": store.visible_cache_keys(tenant_id, subject),
        "recipient_ack": "not_delivered",
        "durable": False,
    }


class VerbRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verb: str = Field(min_length=1, max_length=64)
    lease_id: uuid.UUID | None = None
    model: str | None = Field(default=None, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)


@dataclass
class _Call:
    tenant_id: uuid.UUID
    subject: str
    lease_id: uuid.UUID
    cache: TicketCache
    store: RouterVerbStore


async def _open_verb(
    request: Request,
    *,
    lease_id: uuid.UUID | None,
    model: str | None,
    follow_chat_route: bool = False,
) -> _Call:
    from hypermesh_gateway_service.routes import (
        _authorize_caller,
        _bind_renter_to_ticket,
        _key_policy,
        _optional_lease_id,
        _tickets,
    )

    grant, tenant_id, raw_key = await _authorize_caller(request, ir=False)
    requested = _optional_lease_id(
        request, ChatCompletionRequest(lease_id=lease_id, model=model)
    )
    store = verb_store(request)
    cache = _tickets(request)
    try:
        route_args = dict(
            key=raw_key,
            tenant_id=tenant_id,
            requested_model=model,
            requested_lease_id=requested,
            purposes=RENTER_CHAT_PURPOSES,
            policy=_key_policy(request),
        )
        if follow_chat_route:
            lease = resolve_for_caller(
                store, cache, subject=grant.router_subject, **route_args
            )
        else:
            # Preference management must remain usable when those preferences
            # exclude every route or reference a model that is no longer served.
            lease = resolve_route(cache, **route_args)
    except HostExcluded as exc:
        raise DoorError(
            409,
            "This lease's host is excluded by the router.",
            "host_excluded",
        ) from exc
    except LeaseNotOwned as exc:
        if requested is not None and requested in cache.revoked_lease_ids(tenant_id):
            raise instance_not_ready("not_honored") from exc
        raise DoorError(403, LEASE_NOT_OWNED_MESSAGE, "lease_not_owned") from exc
    except ModelNotFound as exc:
        raise DoorError(
            404,
            model_not_found_message(exc.requested, exc.available),
            "model_not_found",
        ) from exc
    if lease is None:
        raise DoorError(402, no_active_lease_message(), "no_active_lease")
    try:
        claims = require_chat_posture(
            cache,
            tenant_id,
            lease.lease_id,
            peer_up=False,
            require_peer=False,
        )
        require_renter_chat_purpose(claims)
    except TicketNotReady as exc:
        raise instance_not_ready("not_honored") from exc
    _bind_renter_to_ticket(request, grant, claims, tenant_id, cache)
    return _Call(
        tenant_id=tenant_id,
        subject=grant.router_subject,
        lease_id=lease.lease_id,
        cache=cache,
        store=store,
    )


def _respond(
    *,
    spec: VerbSpec | None,
    verb: str,
    lease_id: uuid.UUID | None,
    command_id: str,
    status: str,
    http_status: int,
    wired: bool,
    detail: str,
    recipient_ack: str,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "object": "hypermesh.router_verb",
        "verb": verb,
        "family": spec.family if spec is not None else "unknown",
        "status": status,
        "wired": wired,
        "lease_id": str(lease_id) if lease_id is not None else None,
        "command_id": command_id,
        "recipient_ack": recipient_ack,
        "detail": detail,
    }
    if extra:
        body.update(extra)
    logger.info(
        "router verb=%s status=%s lease=%s command=%s wired=%s",
        verb,
        status,
        lease_id,
        command_id,
        wired,
    )
    return JSONResponse(status_code=http_status, content=body)


async def post_verb(request: Request, body: VerbRequest) -> JSONResponse:
    from hypermesh_gateway_service.routes import _authorize_caller

    spec = _SPECS.get(body.verb)
    if spec is None:
        await _authorize_caller(request, ir=False)
        return _respond(
            spec=None,
            verb=body.verb,
            lease_id=body.lease_id,
            command_id=str(uuid.uuid4()),
            status="unknown_verb",
            http_status=400,
            wired=False,
            detail="Unknown router verb. GET /v1/router/verbs lists the set.",
            recipient_ack="not_applicable",
        )
    call = await _open_verb(
        request, lease_id=body.lease_id, model=body.model,
        follow_chat_route=spec.verb in {"pause", "resume", "drain", "cancel"},
    )
    command_id = str(uuid.uuid4())
    try:
        result = _apply(
            spec,
            call.store,
            tenant_id=call.tenant_id,
            subject=call.subject,
            lease_id=call.lease_id,
            cache=call.cache,
            args=body.args,
            command_id=command_id,
        )
    except VerbError as exc:
        return _respond(
            spec=spec,
            verb=spec.verb,
            lease_id=call.lease_id,
            command_id=command_id,
            status=exc.status,
            http_status=exc.http_status,
            wired=spec.wired and exc.status != "not_wired",
            detail=exc.detail,
            recipient_ack="not_applicable" if exc.status == "denied" else "not_delivered",
            extra=exc.extra,
        )
    status = str(result.pop("status"))
    http_status = 200
    return _respond(
        spec=spec,
        verb=spec.verb,
        lease_id=call.lease_id,
        command_id=command_id,
        status=status,
        http_status=http_status,
        wired=bool(result.pop("wired")),
        detail=str(result.pop("detail")),
        recipient_ack=str(result.pop("recipient_ack")),
        extra=result,
    )


async def get_catalog(request: Request) -> dict[str, Any]:
    from hypermesh_gateway_service.routes import _authorize_caller

    await _authorize_caller(request, ir=False)
    return {
        "object": "hypermesh.router_verb_catalog",
        "verbs": [
            {
                "verb": spec.verb,
                "family": spec.family,
                "wired": spec.wired,
                "summary": spec.summary,
            }
            for spec in VERB_SPECS
        ],
    }


async def get_session(
    request: Request,
    lease_id: uuid.UUID | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    try:
        call = await _open_verb(
            request, lease_id=lease_id, model=model, follow_chat_route=True
        )
        selected = call.lease_id
    except DoorError as exc:
        if exc.code not in {"host_excluded", "model_not_found", "no_active_lease"}:
            raise
        # Still require an owned, valid ticket before exposing preferences, but
        # do not report an unrelated fallback lease as the caller's chat route.
        call = await _open_verb(request, lease_id=lease_id, model=None)
        selected = None
    return _session_view(
        call.store,
        tenant_id=call.tenant_id,
        subject=call.subject,
        lease_id=selected,
    )


async def get_audit(request: Request, lease_id: uuid.UUID | None = None) -> dict[str, Any]:
    call = await _open_verb(request, lease_id=lease_id, model=None)
    return {
        "object": "hypermesh.router_audit_overrides",
        "overrides": [
            {
                "command_id": row.command_id,
                "lease_id": row.lease_id,
                "subject": row.subject,
                "reason": row.reason,
                "decision": row.decision,
                "recorded_at": row.recorded_at,
            }
            for row in call.store.audit_for(call.tenant_id)
        ],
    }


router = APIRouter(prefix="/hypermesh-gateway", tags=["hypermesh-router-verbs"])
openai_router = APIRouter(tags=["hypermesh-router-verbs"])


@router.post("/v1/router/verbs")
async def sibling_post_verb(request: Request, body: VerbRequest) -> JSONResponse:
    return await post_verb(request, body)


@openai_router.post("/v1/router/verbs")
async def openai_post_verb(request: Request, body: VerbRequest) -> JSONResponse:
    return await post_verb(request, body)


@router.get("/v1/router/verbs")
async def sibling_catalog(request: Request) -> dict[str, Any]:
    return await get_catalog(request)


@openai_router.get("/v1/router/verbs")
async def openai_catalog(request: Request) -> dict[str, Any]:
    return await get_catalog(request)


@router.get("/v1/router/session")
async def sibling_session(
    request: Request,
    lease_id: uuid.UUID | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    return await get_session(request, lease_id=lease_id, model=model)


@openai_router.get("/v1/router/session")
async def openai_session(
    request: Request,
    lease_id: uuid.UUID | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    return await get_session(request, lease_id=lease_id, model=model)


@router.get("/v1/router/audit-overrides")
async def sibling_audit(
    request: Request, lease_id: uuid.UUID | None = None
) -> dict[str, Any]:
    return await get_audit(request, lease_id=lease_id)


@openai_router.get("/v1/router/audit-overrides")
async def openai_audit(
    request: Request, lease_id: uuid.UUID | None = None
) -> dict[str, Any]:
    return await get_audit(request, lease_id=lease_id)
