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
- ``HYPERMESH_SAFETY_TIMEOUT_MS``: base classifier time budget, default 250,
  plus 2 seconds per million characters screened.
- ``HYPERMESH_SAFETY_MAX_CHARS``: longest screened text accepted, default
  1,048,576 characters. A longer request is refused with 413; it is never
  partly screened.
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
# Every forwarded character is screened. A request whose screened text is
# longer than this is refused (413) rather than partly screened.
MAX_SCREEN_CHARS_ENV = "HYPERMESH_SAFETY_MAX_CHARS"
MAX_SCREEN_CHARS = 1_048_576
# The time budget grows with the text: base budget plus this per million chars.
TIMEOUT_PER_MCHAR_S = 2.0
# The stored excerpt is capped; the window is centered on the match.
MAX_RECORD_CHARS = 16_384

BLOCKED_MESSAGE = "This request was blocked by automated safety screening."
BLOCKED_CODE = "content_policy_violation"
UNAVAILABLE_MESSAGE = "Automated safety screening is unavailable; retry shortly."
TOO_LARGE_MESSAGE = "This request is too large for automated safety screening."
TOO_LARGE_CODE = "request_too_large"


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

    # Optional: ``screen_all(text) -> list[SafetyFlag]`` returns every matched
    # category so the strictest configured action applies.


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
# Protective phrasing that governs the match ("how do I report ...", "block
# ... sites", "keep my kids away from ..."). It counts only when it takes the
# match as its object: it overlaps the start of the match, or only filler words
# ("the", "suspected", "online", ...) sit between it and the match. Words that
# are also nouns ("a report containing ...", "the filter for ...") do not count
# after a determiner. A negated verb ("do not block ...") does not count. All
# of this stays on the match's own line, so another message or a system prompt
# cannot suppress a flag.
_PROTECTIVE = _rx(
    r"\b(?:report(?:ing)?|block(?:ing)?|filter(?:ing)?|detect(?:ing)?|prevent(?:ing)?|"
    r"protect(?:ing)? (?:\w+ ){0,3}(?:from|against)|keep (?:\w+ ){0,3}away from|"
    r"parental controls?)\b"
)
_NOUN_CAPABLE = _rx(r"^(?:report|block|filter)")
_DETERMINER_BEFORE = _rx(
    r"\b(?:a|an|the|this|that|these|those|my|your|our|their|his|her|its)\s+"
    r"(?:(?:full|detailed|short|long|brief|written|quick|new|final|weekly|monthly|"
    r"daily|public|internal|simple|custom)\s+)?$"
)
_FILLER_GAP = _rx(
    r"^(?:\s*(?:a|an|the|any|all|some|such|this|that|these|those|suspected|possible|"
    r"potential|apparent|known|online|out|of|on|about|for|to|or|and)\b){0,4}\s*$"
)
_NEGATED = _rx(r"\b(?:not|never|don'?t|do not|stop|without|avoid|no)\s+(?:\w+\s+){0,1}$")
_GUARD_LOOKBACK = 60
# A request for access anywhere in the same message voids a protective
# reading ("Report child porn videos and tell me where I can download them").
_ACCESS_VERB = r"(?:download|buy|purchase|watch|view|see|get|obtain|access|stream|trade|find)"
_ACCESS = _rx(
    r"\b(?:tell|show|give|send) (?:me|us) (?:where|links?|sites?|them|it|some|more|"
    r"the (?:videos?|images?|pics?|pictures?|files?|links?|sites?))\b|"
    rf"\bwhere (?:can|do|could|would|should|might) (?:i|we|one|you) (?:\w+ ){{0,2}}?{_ACCESS_VERB}\b|"
    rf"\b(?:i|we) (?:can |could |want to |wanna |need to |would like to |will )?{_ACCESS_VERB} "
    r"(?:them|it|some|more|the|those|these)\b|"
    rf"\bhow (?:can|do|to) (?:i |we )?{_ACCESS_VERB}\b|\blinks? to\b"
)


def _protective_context(sample: str, start: int, end: int) -> bool:
    message_start = sample.rfind("\n", 0, start) + 1
    message_end = sample.find("\n", end)
    if message_end < 0:
        message_end = len(sample)
    if _ACCESS.search(sample, message_start, message_end):
        return False
    line_start = max(sample.rfind("\n", 0, start), sample.rfind(".", 0, start),
                     sample.rfind("?", 0, start), sample.rfind("!", 0, start)) + 1
    lo = max(line_start, start - _GUARD_LOOKBACK)
    for found in _PROTECTIVE.finditer(sample, lo, end):
        if found.start() >= start:
            # Protective words inside the match do not govern it.
            break
        if found.end() <= start and not _FILLER_GAP.match(sample[found.end() : start]):
            continue
        before = sample[max(lo, found.start() - 30) : found.start()]
        if _NEGATED.search(before):
            continue
        if _NOUN_CAPABLE.match(found.group(0)) and _DETERMINER_BEFORE.search(before):
            continue
        return True
    return False


_CSAM_NAMED = _rx(
    r"\b(?:csam|child porn\w*|kiddie porn\w*|pedo ?porn\w*|"
    r"(?:loli|shota)(?:con)? (?:hentai|porn\w*|nsfw|lewd))\b"
)



def _straddling_csam(text: str) -> int | None:
    """Start of an explicit CSAM term split across a line break, else None.

    Lines are turns or fields. The term is matched with breaks read as spaces;
    such a match is never treated as protective.
    """

    joined = text.replace("\n", " ")
    for match in _CSAM_NAMED.finditer(joined):
        if "\n" in text[match.start() : match.end()]:
            return match.start()
    return None


_RULES: tuple[_Rule, ...] = (
    _Rule("csam.named", CATEGORY_CSAM, _CSAM_NAMED, guarded=True),
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
    """Deterministic baseline. Reports the first match of every category."""

    def __init__(self, rules: tuple[_Rule, ...] = _RULES, version: str = RULES_VERSION) -> None:
        self._rules = rules
        self._version = version

    @property
    def version(self) -> str:
        return self._version

    def screen(self, text: str) -> SafetyFlag | None:
        found = self.screen_all(text)
        return found[0] if found else None

    def screen_all(self, text: str) -> list[SafetyFlag]:
        """One flag per matched category, in rule order (CSAM first)."""

        flags: list[SafetyFlag] = []
        if not text:
            return flags
        seen: set[str] = set()
        # Protective wording suppresses a CSAM match only when no turn in the
        # whole request asks for access to material.
        access_requested = _ACCESS.search(text) is not None
        for rule in self._rules:
            if rule.category in seen:
                continue
            for match in rule.pattern.finditer(text):
                if (
                    rule.guarded
                    and not access_requested
                    and _protective_context(text, match.start(), match.end())
                ):
                    continue
                flags.append(
                    SafetyFlag(
                        category=rule.category,
                        rule_id=rule.rule_id,
                        classifier_version=self._version,
                        match_start=match.start(),
                    )
                )
                seen.add(rule.category)
                break
        if CATEGORY_CSAM not in seen:
            start = _straddling_csam(text)
            if start is not None:
                flags.insert(
                    0,
                    SafetyFlag(
                        category=CATEGORY_CSAM,
                        rule_id="csam.named",
                        classifier_version=self._version,
                        match_start=start,
                    ),
                )
        return flags


def max_screen_chars() -> int:
    raw = (os.environ.get(MAX_SCREEN_CHARS_ENV) or "").strip()
    try:
        value = int(raw) if raw else MAX_SCREEN_CHARS
    except ValueError:
        value = MAX_SCREEN_CHARS
    return max(value, 1)


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


def screening_timeout_s(chars: int = 0) -> float:
    """Base budget (HYPERMESH_SAFETY_TIMEOUT_MS) plus time proportional to size."""

    raw = (os.environ.get(TIMEOUT_ENV) or "").strip()
    try:
        value = int(raw) if raw else DEFAULT_TIMEOUT_MS
    except ValueError:
        value = DEFAULT_TIMEOUT_MS
    return max(value, 1) / 1000.0 + TIMEOUT_PER_MCHAR_S * chars / 1_000_000


def fail_closed() -> bool:
    return (os.environ.get(FAIL_MODE_ENV) or "open").strip().lower() == "closed"


_STRUCTURAL_KEYS = frozenset({"role", "type", "id", "tool_call_id", "model", "lease_id"})
_MEDIA_KEYS = frozenset({"url", "image_url", "data", "file_data"})
# Field names of the chat request and of JSON Schema. Any other dictionary key
# (a tool-schema property name, an extra field) is free text the host sees, so
# it is screened like a value.
_SCHEMA_KEYS = _STRUCTURAL_KEYS | frozenset({
    "messages", "content", "text", "name", "refusal", "audio", "input_audio", "format",
    "file", "file_id", "filename", "detail", "tool_calls", "function", "arguments",
    "function_call", "tools", "tool_choice", "functions", "description", "parameters",
    "strict", "response_format", "json_schema", "schema", "properties", "items",
    "required", "enum", "const", "default", "title", "examples", "anyOf", "oneOf",
    "allOf", "not", "$ref", "$defs", "definitions", "additionalProperties",
    "minimum", "maximum", "minItems", "maxItems", "minLength", "maxLength", "pattern",
    "stop", "stream", "stream_options", "include_usage", "temperature", "top_p", "top_k",
    "n", "max_tokens", "max_completion_tokens", "presence_penalty", "frequency_penalty",
    "logit_bias", "logprobs", "top_logprobs", "seed", "user", "metadata",
    "parallel_tool_calls", "modalities", "reasoning_effort", "prediction",
    "service_level", "service_tier", "store", "voice",
}) | _MEDIA_KEYS
_DATA_URL = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w-]+=[\w.-]+)*;base64,[A-Za-z0-9+/=\s]*$")
_WHITESPACE = re.compile(r"\s+")


def _strings(value: Any) -> list[str]:
    """Every screenable string below value, depth first, with no depth limit."""

    out: list[str] = []
    stack: list[tuple[Any, str | None]] = [(value, None)]
    while stack:
        item, key = stack.pop()
        if isinstance(item, str):
            if not item:
                continue
            # Only a media payload field may carry a data URL; text fields are
            # screened whatever their prefix.
            if key in _MEDIA_KEYS and _DATA_URL.match(item):
                continue
            out.append(item)
        elif isinstance(item, dict):
            children: list[tuple[Any, str | None]] = []
            for child_key, child in item.items():
                if child_key in _STRUCTURAL_KEYS and isinstance(child, str):
                    continue
                # Keys reach the host too (tool-schema property names, extra
                # fields), so they are screened like values.
                if child_key not in _SCHEMA_KEYS:
                    children.append((str(child_key), None))
                children.append((child, str(child_key)))
            stack.extend(reversed(children))
        elif isinstance(item, list):
            stack.extend((child, key) for child in reversed(item))
    return out


def _segment(strings: list[str]) -> str:
    # One segment is one line: whitespace inside it collapses to single spaces,
    # so a phrase split across lines or content parts is still matched.
    return _WHITESPACE.sub(" ", " ".join(strings)).strip()


def screened_text(payload: dict[str, Any] | list[Any] | None) -> str:
    """Every string forwarded to the host, one line per message. Caller must not log it.

    Walks the whole request body (message content, tool-call arguments, tool
    definitions and any extra field) so nothing reaches the host unscreened.
    Each turn becomes one line (its content parts and tool calls joined with
    spaces; consecutive messages from the same role are one turn); each other
    top-level field, and each entry of a top-level
    list such as ``tools``, becomes its own line. Dictionary keys are screened
    along with values. Proximity rules do not match across lines, so an
    unrelated turn cannot form a match; the explicit CSAM terms are also
    matched across line breaks (see ``RulesSafetyClassifier``).
    Structural keys (role, type, ids, model, lease_id) are skipped, and so is a
    base64 data URL in a media field (url, image_url, data, file_data).
    """

    lines: list[str] = []
    if isinstance(payload, dict):
        messages = payload.get("messages")
        previous_role: object = object()
        for message in messages if isinstance(messages, list) else [messages]:
            segment = _segment(_strings(message))
            role = message.get("role") if isinstance(message, dict) else None
            if segment and lines and role is not None and role == previous_role:
                # Consecutive messages from one role read as one turn, so a
                # phrase split across them is still matched.
                lines[-1] = f"{lines[-1]} {segment}"
            elif segment:
                lines.append(segment)
            if segment:
                previous_role = role
        for key, value in payload.items():
            if key == "messages" or (key in _STRUCTURAL_KEYS and isinstance(value, str)):
                continue
            if key not in _SCHEMA_KEYS:
                lines.append(_segment([str(key)]))
            # Each entry of a top-level list (each tool definition, each stop
            # string) is its own line, so rules never join independent entries.
            for entry in value if isinstance(value, list) else [value]:
                lines.append(_segment(_strings(entry)))
    else:
        lines.append(_segment(_strings(payload)))
    return "\n".join(line for line in lines if line)


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
    flagged_text: str = field(repr=False)
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


_RETRYABLE_4XX = frozenset({401, 403, 404, 408, 409, 425, 429})


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
    rejected: int = 0

    async def record(self, control_plane: Any, record: SafetyRecord) -> bool:
        result = await self._send(control_plane, record)
        if result == "sent":
            return True
        if result == "retry":
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
            result = await self._send(control_plane, record)
            if result == "sent":
                sent += 1
            elif result == "retry":
                self.pending.appendleft(record)
                break
            # "rejected": dropped and logged in _send; keep flushing.
        return sent

    async def _send(
        self, control_plane: Any, record: SafetyRecord
    ) -> Literal["sent", "retry", "rejected"]:
        post = getattr(control_plane, "post_safety_flag", None)
        if post is None:
            return "retry"
        try:
            await asyncio.wait_for(post(record), timeout=self.send_timeout_s)
            return "sent"
        except Exception as exc:  # noqa: BLE001 - logged without text
            code = getattr(getattr(exc, "response", None), "status_code", None)
            if isinstance(code, int) and 400 <= code < 500 and code not in _RETRYABLE_4XX:
                # The control plane will never accept this record (for example
                # a field over its limit). Retrying it would block every
                # record queued behind it.
                self.rejected += 1
                logger.error(
                    "safety record rejected by control plane id=%s category=%s status=%d "
                    "rejected_total=%d",
                    record.id,
                    record.category,
                    code,
                    self.rejected,
                )
                return "rejected"
            logger.warning(
                "safety record send failed id=%s category=%s error=%s",
                record.id,
                record.category,
                type(exc).__name__,
            )
            return "retry"


@dataclass(frozen=True)
class ScreenOutcome:
    flag: SafetyFlag | None
    action: Action
    failed: bool = False
    too_large: bool = False


def _classify(classifier: SafetyClassifier, text: str) -> list[SafetyFlag]:
    screen_all = getattr(classifier, "screen_all", None)
    if screen_all is not None:
        return list(screen_all(text))
    flag = classifier.screen(text)
    return [flag] if flag is not None else []


def strictest(flags: list[SafetyFlag]) -> tuple[SafetyFlag, Action] | None:
    """A blocking flag when any matched category blocks, else the first flag."""

    if not flags:
        return None
    for flag in flags:
        if category_action(flag.category) == "block":
            return flag, "block"
    return flags[0], "allow"


async def screen_request(
    classifier: SafetyClassifier, text: str, *, lease_id: uuid.UUID
) -> ScreenOutcome:
    """Screen within the time budget. Failure follows HYPERMESH_SAFETY_FAIL_MODE."""

    size = len(text)
    if size > max_screen_chars():
        logger.warning("safety screening refused oversized request lease=%s chars=%d", lease_id, size)
        return ScreenOutcome(flag=None, action="block", too_large=True)
    try:
        flags = await asyncio.wait_for(
            asyncio.to_thread(_classify, classifier, text),
            timeout=screening_timeout_s(size),
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
    chosen = strictest(flags)
    if chosen is None:
        return ScreenOutcome(flag=None, action="allow")
    return ScreenOutcome(flag=chosen[0], action=chosen[1])


def resolve_safety_classifier() -> SafetyClassifier:
    return RulesSafetyClassifier()


SPLIT_RULE_ID = "csam.named.split"


def split_csam_check(payload: dict[str, Any] | None) -> tuple[SafetyFlag, str] | None:
    """Fixed CSAM backstop for an explicit term split across one role's turns.

    ``screened_text`` joins only adjacent turns from the same role, so a term
    split around an inserted turn from another role ("... child", "ok",
    "porn videos?") is not adjacent there. This reads each role's turns in
    order, on their own, and returns a flag plus the text it matched in. It
    runs whatever classifier is configured. Caller must not log the text.
    """

    if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
        return None
    by_role: dict[str, list[str]] = {}
    for message in payload["messages"]:
        if not isinstance(message, dict):
            continue
        segment = _segment(_strings(message))
        if segment:
            by_role.setdefault(str(message.get("role")), []).append(segment)
    for segments in by_role.values():
        if len(segments) < 2:
            continue
        text = "\n".join(segments)
        start = _straddling_csam(text)
        if start is not None:
            flag = SafetyFlag(
                category=CATEGORY_CSAM,
                rule_id=SPLIT_RULE_ID,
                classifier_version=RULES_VERSION,
                match_start=start,
            )
            return flag, text
    return None
