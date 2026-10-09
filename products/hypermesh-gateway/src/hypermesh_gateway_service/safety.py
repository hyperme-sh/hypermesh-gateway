"""Automated safety screening on every chat request through this door.

Screens the request text in process for a small set of severe categories.
Nothing is stored or sent anywhere for a request that is not flagged. A
flagged request is recorded once on the control plane (category, classifier
version, rule, time, account, lease and the flagged text) for operator
review, and is then allowed or blocked by the per-category action.

Prompt text never goes to logs, metrics, telemetry or events. Log lines here
carry the category, action, classifier version and lease id only.

Classifiers are pluggable (``SafetyClassifier``). The bundled baseline is a
deterministic rules classifier; a model-backed classifier can implement the
same protocol later. It must stay in process or behind a bounded call, and
CI must stay hermetic.

Settings (environment):

- ``HYPERMESH_SAFETY_SCREENING``: ``on`` (default) or ``off``.
- ``HYPERMESH_SAFETY_ACTION_SELF_HARM``, ``..._MALWARE_INTRUSION``,
  ``..._VIOLENT_EXTREMISM``: ``allow`` (default) or ``block``. Both record.
  Child sexual abuse material is always ``block``; it cannot be set to allow.
- ``HYPERMESH_SAFETY_TIMEOUT_MS``: classifier time budget, default 250.
- ``HYPERMESH_SAFETY_FAIL_MODE``: what happens when the classifier errors or
  runs past its budget. ``open`` (default) serves the request unscreened
  and logs the failure without text; ``closed`` refuses the request with
  503. Neither stores anything.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

Action = Literal["allow", "block"]

CATEGORY_CSAM = "csam"
CATEGORY_SELF_HARM = "self_harm"
CATEGORY_MALWARE_INTRUSION = "malware_intrusion"
CATEGORY_VIOLENT_EXTREMISM = "violent_extremism"
CATEGORIES = (
    CATEGORY_CSAM,
    CATEGORY_SELF_HARM,
    CATEGORY_MALWARE_INTRUSION,
    CATEGORY_VIOLENT_EXTREMISM,
)
# CSAM is fixed: block and record. The others default to allow and record.
FIXED_BLOCK = frozenset({CATEGORY_CSAM})
DEFAULT_ACTIONS: dict[str, Action] = {
    CATEGORY_CSAM: "block",
    CATEGORY_SELF_HARM: "allow",
    CATEGORY_MALWARE_INTRUSION: "allow",
    CATEGORY_VIOLENT_EXTREMISM: "allow",
}

SCREENING_ENV = "HYPERMESH_SAFETY_SCREENING"
ACTION_ENV_PREFIX = "HYPERMESH_SAFETY_ACTION_"
TIMEOUT_ENV = "HYPERMESH_SAFETY_TIMEOUT_MS"
FAIL_MODE_ENV = "HYPERMESH_SAFETY_FAIL_MODE"
DEFAULT_TIMEOUT_MS = 250
# Text past this many characters is screened as head plus tail, so a huge
# body cannot stretch classification without bound.
MAX_SCREEN_CHARS = 262_144
# The stored excerpt is capped; the window is centered on the match.
MAX_RECORD_CHARS = 16_384

BLOCKED_MESSAGE = "This request was blocked by automated safety screening."
BLOCKED_CODE = "content_policy_violation"
UNAVAILABLE_MESSAGE = "Automated safety screening is unavailable; retry shortly."


@dataclass(frozen=True)
class SafetyFlag:
    category: str
    rule_id: str
    classifier_version: str
    match_start: int = 0


@runtime_checkable
class SafetyClassifier(Protocol):
    """Pluggable screen. Returns the first flag, or None when nothing matched.

    Implementations must not log, persist or publish the text they receive.
    """

    @property
    def version(self) -> str: ...

    def screen(self, text: str) -> SafetyFlag | None: ...


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    # Protective phrasing on the same line, directly before or inside the
    # match, suppresses the rule.
    guarded: bool = False


def _rx(source: str) -> re.Pattern[str]:
    # No DOTALL: "." never crosses a newline, and screened_text() joins
    # messages and fields with newlines, so proximity rules stay within one
    # line of one field.
    return re.compile(source, re.IGNORECASE)


_MINOR = (
    r"(?:child(?:ren)?|kids?|minors?|underage|under-age|pre-?teens?|toddlers?|"
    r"infants?|(?:elementary|middle|grade)[ -]school(?:ers?)?|"
    r"(?:[1-9]|1[0-7])[ -]?(?:years?|yrs?)[ -]?old|(?:[1-9]|1[0-7])[ -]?yo)"
)
_SEXUAL = (
    r"(?:porn\w*|erotic\w*|sexually explicit|explicit sex\w*|nsfw|lewd|"
    r"sex with|having sex|sexual (?:roleplay|role-play|story|fantasy|content|scene)s?|"
    r"(?:nude|naked) (?:photo|pic|picture|image|video|selfie)s?)"
)
# Protective phrasing directly governing the match ("how do I report ...",
# "keep my kids away from ...", "parental controls for ..."). It only counts
# inside the same line as the match, so another message (each message is its
# own line group) or a system prompt cannot suppress a flag, and a negated
# verb ("do not block ...") does not count.
_PROTECTIVE = _rx(
    r"\b(?:report(?:ing)?|block(?:ing)?|filter(?:ing)?|detect(?:ing)?|prevent(?:ing)?|"
    r"protect(?:ing)? (?:\w+ ){0,3}(?:from|against)|keep (?:\w+ ){0,3}away from|"
    r"parental controls?)\b"
)
_NEGATED = _rx(r"\b(?:not|never|don'?t|do not|stop|without|avoid|no)\s+(?:\w+\s+){0,1}$")
_GUARD_LOOKBACK = 60


def _protective_context(sample: str, start: int, end: int) -> bool:
    line_start = max(sample.rfind("\n", 0, start), sample.rfind(".", 0, start),
                     sample.rfind("?", 0, start), sample.rfind("!", 0, start)) + 1
    lo = max(line_start, start - _GUARD_LOOKBACK)
    for found in _PROTECTIVE.finditer(sample, lo, end):
        if _NEGATED.search(sample, max(lo, found.start() - 30), found.start()):
            continue
        return True
    return False


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "csam.named",
        CATEGORY_CSAM,
        _rx(r"\b(?:csam|child porn\w*|kiddie porn\w*|pedo ?porn\w*|"
            r"(?:loli|shota)(?:con)? (?:hentai|porn\w*|nsfw|lewd))\b"),
        guarded=True,
    ),
    _Rule(
        "csam.minor_sexual",
        CATEGORY_CSAM,
        _rx(rf"\b{_MINOR}\b.{{0,60}}\b{_SEXUAL}|\b{_SEXUAL}.{{0,60}}\b{_MINOR}\b"),
        guarded=True,
    ),
    _Rule(
        "self_harm.intent",
        CATEGORY_SELF_HARM,
        _rx(r"\bi(?: am|'m| will|'ll)? ?(?:going to|gonna|want to|wanna|plan(?:ning)? to|about to)"
            r" (?:kill myself|end my (?:own )?life|commit suicide|take my (?:own )?life|"
            r"hurt myself|cut myself|overdose)\b"),
    ),
    _Rule(
        "self_harm.method",
        CATEGORY_SELF_HARM,
        _rx(r"\b(?:best|easiest|quickest|painless(?:ly)?|surest) (?:way|method)s? to "
            r"(?:kill myself|commit suicide|end my life|die)\b|"
            r"\bhow (?:many|much) [\w ]{0,40}(?:pills|tablets|tylenol|acetaminophen|"
            r"paracetamol|insulin)[\w ]{0,40}\b(?:to die|to kill myself|lethal|to overdose)\b|"
            r"\b(?:write|writing|help me write) (?:my|a) suicide note\b|"
            r"\bi (?:don'?t|do not) want to (?:live|be alive) anymore\b"),
    ),
    _Rule(
        "malware.build",
        CATEGORY_MALWARE_INTRUSION,
        _rx(r"\b(?:write|create|build|code|make|develop|generate|program)\b.{0,60}\b"
            r"(?:ransomware|keylogger|credential stealer|info-?stealer|botnet|rootkit|"
            r"remote access trojan|crypto-?jacker|wiper malware|self-?propagating worm)\b"),
    ),
    _Rule(
        "malware.evasion",
        CATEGORY_MALWARE_INTRUSION,
        _rx(r"\b(?:fully undetectable|fud) (?:payload|crypter|malware|rat|loader)\b|"
            r"\b(?:bypass|evade|disable) (?:edr|antivirus|anti-virus|defender)\b.{0,60}"
            r"\b(?:payload|malware|implant|ransomware)\b"),
    ),
    _Rule(
        "intrusion.target",
        CATEGORY_MALWARE_INTRUSION,
        _rx(r"\b(?:hack|break) into (?:my (?:ex|neighbou?r|boss|coworker|co-worker)|"
            r"(?:someone|somebody|another person)(?:'s)?|his|her|their)\b|"
            r"\b(?:phishing (?:page|kit|site)|credential harvest\w*)\b.{0,60}"
            r"\b(?:steal|capture|harvest) (?:\w+ )?(?:passwords?|credentials|logins?)\b"),
    ),
    _Rule(
        "extremism.group",
        CATEGORY_VIOLENT_EXTREMISM,
        _rx(r"\b(?:join|recruit\w*(?: for| to)?|pledge (?:allegiance|bay'?ah) to|"
            r"(?:write|create) (?:propaganda|a manifesto|recruitment \w+) for)\b.{0,40}\b"
            r"(?:isis|isil|islamic state|daesh|al[- ]?qa'?eda|al[- ]?shabaab|boko haram|"
            r"atomwaffen)\b"),
    ),
    _Rule(
        "extremism.attack",
        CATEGORY_VIOLENT_EXTREMISM,
        _rx(r"\b(?:make|build|assemble|construct)\b.{0,30}\b(?:pipe bomb|ied|car bomb|"
            r"suicide vest|pressure[- ]cooker bomb|nail bomb)s?\b|"
            r"\bmaximi[sz]e (?:the )?(?:casualties|body count|deaths|death toll)\b|"
            r"\b(?:plan(?:ning)?|carry out|best (?:place|target)s? for)\b.{0,40}"
            r"\b(?:mass shooting|terror(?:ist)? attack|massacre)\b"),
    ),
)

RULES_VERSION = "safety-rules-v1"


class RulesSafetyClassifier:
    """Deterministic baseline. First matching rule wins, CSAM rules first."""

    def __init__(self, rules: tuple[_Rule, ...] = _RULES, version: str = RULES_VERSION) -> None:
        self._rules = rules
        self._version = version

    @property
    def version(self) -> str:
        return self._version

    def screen(self, text: str) -> SafetyFlag | None:
        if not text:
            return None
        sample = bounded_sample(text)
        for rule in self._rules:
            for match in rule.pattern.finditer(sample):
                if rule.guarded and _protective_context(sample, match.start(), match.end()):
                    continue
                return SafetyFlag(
                    category=rule.category,
                    rule_id=rule.rule_id,
                    classifier_version=self._version,
                    match_start=_original_offset(text, match.start()),
                )
        return None


def bounded_sample(text: str) -> str:
    """Whitespace-collapsed text, capped to head plus tail."""

    if len(text) > MAX_SCREEN_CHARS:
        head = MAX_SCREEN_CHARS * 3 // 4
        tail = MAX_SCREEN_CHARS - head
        text = text[:head] + "\n" + text[-tail:]
    return text


def _original_offset(text: str, offset: int) -> int:
    if len(text) <= MAX_SCREEN_CHARS:
        return offset
    head = MAX_SCREEN_CHARS * 3 // 4
    if offset <= head:
        return offset
    return len(text) - (MAX_SCREEN_CHARS - head) + (offset - head - 1)


def record_excerpt(text: str, match_start: int) -> str:
    """The flagged text, capped and centered on the match."""

    if len(text) <= MAX_RECORD_CHARS:
        return text
    start = max(0, min(match_start - MAX_RECORD_CHARS // 2, len(text) - MAX_RECORD_CHARS))
    return text[start : start + MAX_RECORD_CHARS]


def screening_enabled() -> bool:
    raw = (os.environ.get(SCREENING_ENV) or "on").strip().lower()
    return raw not in {"0", "off", "false", "no", "disabled"}


def category_action(category: str) -> Action:
    if category in FIXED_BLOCK:
        return "block"
    default = DEFAULT_ACTIONS.get(category, "allow")
    raw = (os.environ.get(ACTION_ENV_PREFIX + category.upper()) or "").strip().lower()
    if raw in {"allow", "block"}:
        return raw  # type: ignore[return-value]
    return default


def screening_timeout_s() -> float:
    raw = (os.environ.get(TIMEOUT_ENV) or "").strip()
    try:
        value = int(raw) if raw else DEFAULT_TIMEOUT_MS
    except ValueError:
        value = DEFAULT_TIMEOUT_MS
    return max(value, 1) / 1000.0


def fail_closed() -> bool:
    return (os.environ.get(FAIL_MODE_ENV) or "open").strip().lower() == "closed"


_STRUCTURAL_KEYS = frozenset({"role", "type", "id", "tool_call_id", "model", "lease_id"})
_MEDIA_KEYS = frozenset({"url", "image_url", "data", "file_data"})
_DATA_URL = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w-]+=[\w.-]+)*;base64,[A-Za-z0-9+/=\s]*$")
_MAX_DEPTH = 32


def screened_text(payload: dict[str, Any] | list[Any] | None) -> str:
    """Every string forwarded to the host, messages first. Caller must not log it.

    Walks the whole request body (message content, tool-call arguments, tool
    definitions and any extra field) so nothing reaches the host unscreened.
    Structural keys (role, type, ids, model, lease_id) are skipped, and so is a
    base64 data URL in a media field (url, image_url, data, file_data).
    """

    parts: list[str] = []

    def walk(value: Any, depth: int, key: str | None = None) -> None:
        if depth > _MAX_DEPTH:
            return
        if isinstance(value, str):
            if not value:
                return
            # Only a media payload field may carry a data URL; text fields are
            # screened whatever their prefix.
            if key in _MEDIA_KEYS and _DATA_URL.match(value):
                return
            parts.append(value)
        elif isinstance(value, dict):
            for child_key, item in value.items():
                if child_key in _STRUCTURAL_KEYS and isinstance(item, str):
                    continue
                walk(item, depth + 1, str(child_key))
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1, key)

    if isinstance(payload, dict):
        walk(payload.get("messages"), 0)
        walk({k: v for k, v in payload.items() if k != "messages"}, 0)
    else:
        walk(payload, 0)
    return "\n".join(parts)


@dataclass(frozen=True)
class SafetyRecord:
    """One flagged request, as sent to the control plane for review."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    lease_id: uuid.UUID
    subject: str
    category: str
    action: Action
    rule_id: str
    classifier_version: str
    door: str
    flagged_text: str
    occurred_at: datetime

    def as_body(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "lease_id": str(self.lease_id),
            "subject": self.subject,
            "category": self.category,
            "action": self.action,
            "rule_id": self.rule_id,
            "classifier_version": self.classifier_version,
            "door": self.door,
            "flagged_text": self.flagged_text,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat(),
        }

    def __repr__(self) -> str:  # never print the text
        return (
            f"SafetyRecord(id={self.id}, category={self.category}, action={self.action}, "
            f"classifier_version={self.classifier_version})"
        )


_MAX_PENDING = 1000


@dataclass
class SafetyRecorder:
    """Sends flagged records to the control plane.

    A record that cannot be sent waits in process memory (never on disk) and
    is retried by the refresh loop. At most ``max_pending`` records wait; past
    that the oldest is evicted, counted in ``dropped`` and logged at error
    level (id and category only). A restart drops records still waiting.
    """

    pending: deque[SafetyRecord] = field(default_factory=deque)
    send_timeout_s: float = 2.0
    max_pending: int = _MAX_PENDING
    dropped: int = 0

    async def record(self, control_plane: Any, record: SafetyRecord) -> bool:
        if await self._send(control_plane, record):
            return True
        self._enqueue(record)
        return False

    def _enqueue(self, record: SafetyRecord) -> None:
        """Keep the newest records. Every eviction is counted and logged."""

        while len(self.pending) >= self.max_pending:
            lost = self.pending.popleft()
            self.dropped += 1
            logger.error(
                "safety record dropped: pending queue full id=%s category=%s dropped_total=%d",
                lost.id,
                lost.category,
                self.dropped,
            )
        self.pending.append(record)

    async def flush(self, control_plane: Any) -> int:
        sent = 0
        for _ in range(len(self.pending)):
            record = self.pending.popleft()
            if await self._send(control_plane, record):
                sent += 1
            else:
                self.pending.append(record)
                break
        return sent

    async def _send(self, control_plane: Any, record: SafetyRecord) -> bool:
        post = getattr(control_plane, "post_safety_flag", None)
        if post is None:
            return False
        try:
            await asyncio.wait_for(post(record), timeout=self.send_timeout_s)
            return True
        except Exception as exc:  # noqa: BLE001 - logged without text
            logger.warning(
                "safety record send failed id=%s category=%s error=%s",
                record.id,
                record.category,
                type(exc).__name__,
            )
            return False


@dataclass(frozen=True)
class ScreenOutcome:
    flag: SafetyFlag | None
    action: Action
    failed: bool = False


async def screen_request(
    classifier: SafetyClassifier, text: str, *, lease_id: uuid.UUID
) -> ScreenOutcome:
    """Screen within the time budget. Failure follows HYPERMESH_SAFETY_FAIL_MODE."""

    try:
        flag = await asyncio.wait_for(
            asyncio.to_thread(classifier.screen, text), timeout=screening_timeout_s()
        )
    except Exception as exc:  # noqa: BLE001 - includes TimeoutError
        closed = fail_closed()
        logger.error(
            "safety screening failed lease=%s version=%s error=%s fail_mode=%s",
            lease_id,
            getattr(classifier, "version", "unknown"),
            type(exc).__name__,
            "closed" if closed else "open",
        )
        return ScreenOutcome(flag=None, action="block" if closed else "allow", failed=True)
    if flag is None:
        return ScreenOutcome(flag=None, action="allow")
    return ScreenOutcome(flag=flag, action=category_action(flag.category))


def resolve_safety_classifier() -> SafetyClassifier:
    return RulesSafetyClassifier()
