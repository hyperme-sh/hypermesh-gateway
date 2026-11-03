"""Hermetic IR taxonomy pack: structured classes + matchers.

Loaded from versioned JSON. No live model RPC. Not a detector.
Not a CASB. Prompt text is classified in-process and must not be logged.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hypermesh_gateway_service.classify import (
    CLASS_OUT_OF_SCOPE,
    Classification,
    Classifier,
    Decision,
)

logger = logging.getLogger(__name__)

BUNDLED_PACK_NAME = "ir-taxonomy-v1.json"
CLOSED_PACK_VERSION = "closed"


def normalize_prompt(text: str) -> str:
    """Collapse whitespace and case for matching only. Do not log the result."""

    return " ".join((text or "").lower().split())


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def match_node(node: Any, blob: str) -> bool:
    """Evaluate a structured matcher against already-normalized text."""

    if not isinstance(node, dict):
        return False
    if "any" in node:
        items = _as_list(node["any"])
        return any(match_node(item, blob) for item in items)
    if "all" in node:
        items = _as_list(node["all"])
        return bool(items) and all(match_node(item, blob) for item in items)
    if "not" in node:
        return not match_node(node["not"], blob)
    if "phrase" in node:
        phrase = normalize_prompt(str(node["phrase"]))
        return bool(phrase) and phrase in blob
    if "token" in node:
        token = normalize_prompt(str(node["token"]))
        if not token:
            return False
        return re.search(rf"\b{re.escape(token)}\b", blob) is not None
    if "regex" in node:
        pattern = str(node["regex"])
        try:
            return re.search(pattern, blob, flags=re.IGNORECASE) is not None
        except re.error:
            return False
    return False


@dataclass(frozen=True)
class TaxonomyClass:
    id: str
    disposition: Decision
    label: str = ""


@dataclass(frozen=True)
class TaxonomyRule:
    id: str
    prompt_class: str
    priority: int
    match: dict[str, Any]


@dataclass(frozen=True)
class TaxonomyPack:
    version: str
    classes: dict[str, TaxonomyClass]
    rules: tuple[TaxonomyRule, ...]
    default_class: str = CLASS_OUT_OF_SCOPE
    default_disposition: Decision = "hold"

    def disposition_for(self, class_id: str) -> Decision:
        found = self.classes.get(class_id)
        if found is None:
            return self.default_disposition
        return found.disposition


def _require_decision(value: Any, *, field: str) -> Decision:
    if value not in {"allow", "hold"}:
        raise ValueError(f"invalid {field}")
    return value


def load_taxonomy_pack(payload: dict[str, Any]) -> TaxonomyPack:
    """Parse and validate a pack dict. Raises ValueError on a bad pack."""

    version = str(payload.get("version") or "").strip()
    if not version:
        raise ValueError("pack version required")
    default = payload.get("default")
    if not isinstance(default, dict):
        raise ValueError("pack default required")
    default_class = str(default.get("class") or "").strip() or CLASS_OUT_OF_SCOPE
    default_disposition = _require_decision(default.get("disposition"), field="default.disposition")
    classes: dict[str, TaxonomyClass] = {}
    for item in _as_list(payload.get("classes")):
        if not isinstance(item, dict):
            raise ValueError("class must be an object")
        class_id = str(item.get("id") or "").strip()
        if not class_id:
            raise ValueError("class id required")
        classes[class_id] = TaxonomyClass(
            id=class_id,
            disposition=_require_decision(item.get("disposition"), field=f"class {class_id}"),
            label=str(item.get("label") or ""),
        )
    if default_class not in classes:
        raise ValueError("default class missing from classes")
    rules: list[TaxonomyRule] = []
    for item in _as_list(payload.get("rules")):
        if not isinstance(item, dict):
            raise ValueError("rule must be an object")
        rule_id = str(item.get("id") or "").strip()
        prompt_class = str(item.get("class") or "").strip()
        match = item.get("match")
        if not rule_id or not prompt_class:
            raise ValueError("rule id and class required")
        if prompt_class not in classes:
            raise ValueError(f"rule {rule_id} class unknown")
        if not isinstance(match, dict) or not match:
            raise ValueError(f"rule {rule_id} match required")
        priority = item.get("priority", 100)
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError(f"rule {rule_id} priority must be int")
        rules.append(
            TaxonomyRule(
                id=rule_id,
                prompt_class=prompt_class,
                priority=priority,
                match=match,
            )
        )
    rules.sort(key=lambda rule: (rule.priority, rule.id))
    return TaxonomyPack(
        version=version,
        classes=classes,
        rules=tuple(rules),
        default_class=default_class,
        default_disposition=default_disposition,
    )


def load_taxonomy_pack_file(path: str | Path) -> TaxonomyPack:
    raw = Path(path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("pack must be an object")
    return load_taxonomy_pack(payload)


def bundled_pack_path() -> Path:
    return Path(__file__).resolve().parent / "packs" / BUNDLED_PACK_NAME


class TaxonomyPackClassifier:
    """Rule/taxonomy classifier. Swap via the Classifier protocol."""

    def __init__(self, pack: TaxonomyPack) -> None:
        self._pack = pack

    @property
    def pack_version(self) -> str:
        return self._pack.version

    @classmethod
    def from_path(cls, path: str | Path) -> TaxonomyPackClassifier:
        return cls(load_taxonomy_pack_file(path))

    @classmethod
    def from_bundled(cls) -> Classifier:
        try:
            return cls.from_path(bundled_pack_path())
        except (OSError, json.JSONDecodeError, ValueError):
            logger.info("ir taxonomy pack unavailable; holding closed")
            return ClosedClassifier()

    def classify(self, text: str) -> Classification:
        blob = normalize_prompt(text)
        if not blob:
            return Classification(
                self._pack.default_class,
                self._pack.default_disposition,
                pack_version=self.pack_version,
            )
        for rule in self._pack.rules:
            if match_node(rule.match, blob):
                return Classification(
                    rule.prompt_class,
                    self._pack.disposition_for(rule.prompt_class),
                    pack_version=self.pack_version,
                    rule_id=rule.id,
                )
        return Classification(
            self._pack.default_class,
            self._pack.default_disposition,
            pack_version=self.pack_version,
        )


class ClosedClassifier:
    """Fail closed when a pack cannot load. Still a Classifier."""

    pack_version = CLOSED_PACK_VERSION

    def classify(self, text: str) -> Classification:
        del text
        return Classification(
            CLASS_OUT_OF_SCOPE,
            "hold",
            pack_version=self.pack_version,
            rule_id="closed",
        )
