"""Opt-in IR door classifier. Small set. Allow or hold.

Authorized security work on a model they are allowed to use.
Not a CASB. Not jailbreak-as-a-service. Not marketed as a detector.
This taxonomy is for the IR door only; default chat does not run it.
Automated safety screening (``safety.py``) is separate and runs on every
door.

The keyword stub is gone. Classification is a versioned taxonomy pack
of structured classes + matchers. A later model-backed pack can implement
the same Classifier protocol without changing the IR door.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, Protocol, runtime_checkable

Decision = Literal["allow", "hold"]

CLASS_INCIDENT_TRIAGE = "incident_triage"
CLASS_VULN_REVIEW = "vuln_review"
CLASS_MALWARE_ANALYSIS = "malware_analysis"
CLASS_OUT_OF_SCOPE = "out_of_scope"
CLASS_POLICY_REVIEW = "policy_review"

ALLOW_CLASSES = frozenset(
    {
        CLASS_INCIDENT_TRIAGE,
        CLASS_VULN_REVIEW,
        CLASS_MALWARE_ANALYSIS,
        CLASS_POLICY_REVIEW,
    }
)
PROMPT_CLASSES = ALLOW_CLASSES | {CLASS_OUT_OF_SCOPE}

TAXONOMY_PACK_ENV = "HYPERMESH_IR_TAXONOMY_PACK"


@dataclass(frozen=True)
class Classification:
    prompt_class: str
    decision: Decision
    pack_version: str = ""
    rule_id: str = ""

    @property
    def what_left(self) -> str:
        return "completion" if self.decision == "allow" else "none"


@runtime_checkable
class Classifier(Protocol):
    """Pluggable IR classifier. Door depends on this, not a pack format.

    A later model-backed implementation can swap here. It must stay
    hermetic in CI (no live model RPC) and must never log prompt bodies.
    """

    @property
    def pack_version(self) -> str: ...

    def classify(self, text: str) -> Classification: ...


def prompt_text_from_messages(messages: list[dict[str, Any]] | None) -> str:
    """Join user-visible message text for classify only. Caller must not log it."""

    parts: list[str] = []
    for item in messages or []:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
    return "\n".join(parts)


def classify_prompt(text: str) -> Classification:
    """Small-set classify via the bundled taxonomy pack. Unknown is hold."""

    return resolve_classifier().classify(text)


@lru_cache(maxsize=1)
def default_classifier() -> Classifier:
    from hypermesh_gateway_service.taxonomy import TaxonomyPackClassifier

    return TaxonomyPackClassifier.from_bundled()


def resolve_classifier(path: str | os.PathLike[str] | None = None) -> Classifier:
    """Load a pack from path or HYPERMESH_IR_TAXONOMY_PACK, else bundled v1.

    A missing or invalid override pack fails closed (hold). Prompt text
    is never logged.
    """

    from hypermesh_gateway_service.taxonomy import ClosedClassifier, TaxonomyPackClassifier

    override = path if path is not None else os.environ.get(TAXONOMY_PACK_ENV)
    if override is not None and str(override).strip():
        try:
            return TaxonomyPackClassifier.from_path(override)
        except (OSError, ValueError):
            return ClosedClassifier()
    return default_classifier()
