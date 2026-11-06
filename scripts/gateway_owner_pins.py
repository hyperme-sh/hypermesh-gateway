#!/usr/bin/env python3
"""Reviewed test-plane owner images for the gateway post-deploy smoke.

The deployed image manifest records the fleet publish under test. The test
VM also runs owner-repo images selected in FyberLabs/infra
(``config/deployments/verification-owner-candidates.json``,
``config/test-standalone-owners.json``, and
``config/test-standalone-gateway.json``). Those processes report the owner
commit. A publish matches when the reported identity is that reviewed pin
or the manifest image.

A live read of FyberLabs/infra wins when the job token can see it. This
module only sends GET requests. The snapshot committed beside the smoke
workflow is the pin when that read is unavailable. A git sha that matches
neither source is still behind. A digest or build stamp that disagrees
with the pin is not that pin.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

SNAPSHOT_PATH = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "gateway-owner-pins.json"
)
INFRA_REPO = "FyberLabs/infra"
INFRA_PATHS = (
    "config/deployments/verification-owner-candidates.json",
    "config/test-standalone-owners.json",
    "config/test-standalone-gateway.json",
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_IMAGE_KEYS = {"marketplace-service": "marketplace"}
_GITHUB_API = "https://api.github.com/"


@dataclass(frozen=True)
class OwnerPin:
    service: str
    repository: str
    source_sha: str
    built_at: str = ""
    digest: str = ""


def image_key(service: str) -> str:
    return _IMAGE_KEYS.get(service, service)


def _sha(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    return text if _SHA.fullmatch(text) else ""


def _digest(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text if _DIGEST.fullmatch(text) else ""


def _stamp(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    return text if _STAMP.fullmatch(text) else ""


def _repository(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    return text if _REPO.fullmatch(text) else ""


def _pin_from_row(service: str, row: Mapping[str, object]) -> OwnerPin | None:
    name = str(row.get("compose_service") or service).strip()
    source = _sha(row.get("source_sha"))
    repository = _repository(row.get("repository"))
    if not name or not source or not repository:
        return None
    return OwnerPin(
        service=name,
        repository=repository,
        source_sha=source,
        built_at=_stamp(row.get("built_at")),
        digest=_digest(row.get("image")) or _digest(row.get("digest")),
    )


def pins_from_document(document: object) -> dict[str, OwnerPin]:
    """Pins from one infra JSON document. Invalid rows are dropped."""

    if not isinstance(document, Mapping):
        return {}
    found: dict[str, OwnerPin] = {}
    services = document.get("services")
    if isinstance(services, Mapping):
        for key, row in services.items():
            if not isinstance(row, Mapping):
                continue
            pin = _pin_from_row(str(key), row)
            if pin is not None:
                found[pin.service] = pin
    single = document.get("service")
    if isinstance(single, Mapping):
        pin = _pin_from_row("hypermesh-gateway", single)
        if pin is not None:
            found["hypermesh-gateway"] = pin
    return found


def merge_pins(*groups: Mapping[str, OwnerPin]) -> dict[str, OwnerPin]:
    """Later groups overlay earlier ones, so the runtime pin wins."""

    merged: dict[str, OwnerPin] = {}
    for group in groups:
        merged.update(group)
    return merged


def pin_matches(
    pin: OwnerPin,
    *,
    git_sha: object,
    built_at: object = "",
    image_digest: object = "",
) -> bool:
    """True when this process is the reviewed owner image.

    The source sha is required. A reported digest or build stamp that
    disagrees with the pin is not the same image. A process that omits
    those fields still matches on the sha.
    """

    if _sha(git_sha) != pin.source_sha:
        return False
    stamp = _stamp(built_at)
    if pin.built_at and stamp and stamp != pin.built_at:
        return False
    digest = _digest(image_digest)
    if pin.digest and digest and digest != pin.digest:
        return False
    return True


def lookup_pin(pins: Mapping[str, OwnerPin], service: str) -> OwnerPin | None:
    return pins.get(image_key(service)) or pins.get(service)


def load_snapshot(path: Path | None = None) -> dict[str, OwnerPin]:
    file = path or SNAPSHOT_PATH
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return pins_from_document(document)


def _token() -> str:
    return (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()


def fetch_infra_pins(fetch, token: str, timeout: float) -> dict[str, OwnerPin]:
    """Read the three infra pin documents. Empty when the candidates file is unreadable."""

    groups: list[dict[str, OwnerPin]] = []
    for index, path in enumerate(INFRA_PATHS):
        url = f"https://api.github.com/repos/{INFRA_REPO}/contents/{path}?ref=heads/main"
        status, document = fetch(url, token, timeout, "application/vnd.github.raw")
        if status != 200 or not isinstance(document, Mapping):
            if index == 0:
                return {}
            continue
        groups.append(pins_from_document(document))
    if not groups or not groups[0]:
        return {}
    return merge_pins(*groups)


def _default_fetch(url: str, token: str, timeout: float, accept: str) -> tuple[int, object]:
    if not url.startswith(_GITHUB_API):
        return 0, None
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "hypermesh-gateway-owner-pins",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return 0, None


def load_owner_pins_from(
    fetch=None,
    token: str | None = None,
    timeout: float = 15.0,
) -> tuple[dict[str, OwnerPin], str]:
    """Live infra pins when readable, otherwise the reviewed snapshot.

    The origin label is ``infra`` or ``snapshot``.
    """

    bearer = _token() if token is None else token.strip()
    getter = fetch if fetch is not None else _default_fetch
    if bearer:
        try:
            live = fetch_infra_pins(getter, bearer, timeout)
        except (OSError, ValueError, KeyError, TypeError, TimeoutError):
            live = {}
        if live:
            return live, "infra"
    return load_snapshot(), "snapshot"


def load_owner_pins(
    fetch=None,
    token: str | None = None,
    timeout: float = 15.0,
) -> dict[str, OwnerPin]:
    """Live infra pins when readable, otherwise the reviewed snapshot."""

    pins, _origin = load_owner_pins_from(fetch, token, timeout)
    return pins
