#!/usr/bin/env python3
"""Post-deploy revision check for the gateway smoke.

Before any lease or session call, poll ``GET /api/v1/hypermesh/ready`` until
``x-hypermesh-revision`` is the expected deploy sha or the reviewed owner
pin for hypermesh-service. When the image manifest names images built at
that sha, ``GET /versions`` must report that sha or each service's owner
pin. A digest or build stamp that disagrees with the pin is not the pin.
A sha that matches neither the pin nor the manifest fails.

The manifest is read from the fleet repository (FyberLabs/panopticon
``deploy/image-manifest``). FyberLabs/infra is read only for owner pins.
This command does not deploy, mint a key, or open a lease.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


def _load_owners():
    path = Path(__file__).resolve().parent / "gateway_owner_pins.py"
    spec = importlib.util.spec_from_file_location("gateway_owner_pins", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load owner pins from {path}")
    module = sys.modules.get(spec.name)
    if module is None:
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


_owners = _load_owners()
OwnerPin = _owners.OwnerPin
image_key = _owners.image_key
load_owner_pins_from = _owners.load_owner_pins_from
lookup_pin = _owners.lookup_pin
pin_matches = _owners.pin_matches

API_BASE = "https://api.test.hyperme.sh"
FLEET_REPOSITORY = "FyberLabs/panopticon"
READY_PATH = "/api/v1/hypermesh/ready"
VERSIONS_PATH = "/versions"
REVISION_HEADER = "x-hypermesh-revision"
MANIFEST_BRANCH = "deploy/image-manifest"
MANIFEST_PATH = "image-manifest.json"
MANIFEST_LOOKBACK = 20
ROLLOUT_WAIT_S = 600.0
ROLLOUT_POLL_S = 10.0
_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_API = "https://api.github.com/"
PlaneCall = Callable[[str, str], tuple[int, Mapping[str, str], object]]


@dataclass(frozen=True)
class ManifestImage:
    service: str
    built_git_sha: str
    digest: str = ""
    built_at: str = ""


@dataclass(frozen=True)
class RolloutResult:
    status: str
    detail: str
    deployed: str
    expected: str
    elapsed_s: float
    http_status: int
    missing: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == "pass"


def _sha(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    return text if _SHA.fullmatch(text) else ""


def _format_seconds(elapsed: float) -> str:
    if abs(elapsed - round(elapsed)) < 1e-6:
        return str(int(round(elapsed)))
    return f"{elapsed:.1f}"


class RevisionError(ValueError):
    """A dispatcher asked for a revision that is not a full commit sha."""

    def __init__(self, requested: str) -> None:
        self.requested = requested
        super().__init__(
            "HYPERMESH_SMOKE_EXPECT_REVISION "
            f"{requested!r} is not a full 40-character commit sha"
        )


def expected_revision(raw: str | None = None) -> str:
    """Deploy sha to wait for. Empty records the header and does not wait.

    A nonempty value that is not a full 40-character commit sha is rejected.
    It is not treated as an omitted revision.
    """

    text = os.environ.get("HYPERMESH_SMOKE_EXPECT_REVISION", "") if raw is None else raw
    if not isinstance(text, str):
        raise RevisionError(type(text).__name__)
    stripped = text.strip()
    if not stripped:
        return ""
    sha = _sha(stripped)
    if not sha:
        shown = stripped if len(stripped) <= 80 else stripped[:80] + "…"
        raise RevisionError(shown)
    return sha


def rollout_wait_s() -> float:
    raw = os.environ.get("HYPERMESH_SMOKE_ROLLOUT_WAIT_S", "").strip()
    if not raw:
        return ROLLOUT_WAIT_S
    try:
        value = float(raw)
    except ValueError:
        return ROLLOUT_WAIT_S
    if value < 0:
        return ROLLOUT_WAIT_S
    return value


def images_built_in_manifest(document: object, sha: str) -> dict[str, ManifestImage] | None:
    """Images built at ``sha``. Empty when every row was carried.

    None when the document is not the manifest for ``sha``, or no row has a
    baked sha. An empty mapping means the publish only retagged earlier
    images, so ``/versions`` keeps those bakes.
    """

    want = _sha(sha)
    if not want or not isinstance(document, dict):
        return None
    recorded = document.get("git_sha")
    if _sha(recorded) != want:
        return None
    rows = document.get("services")
    if not isinstance(rows, list) or not rows:
        return None
    built: dict[str, ManifestImage] = {}
    saw_bake = False
    for item in rows:
        if not isinstance(item, dict):
            continue
        name = item.get("service")
        baked = _sha(item.get("built_git_sha"))
        if not isinstance(name, str) or not name.strip() or not baked:
            continue
        saw_bake = True
        if baked != want:
            continue
        key = image_key(name.strip())
        digest = item.get("digest") if isinstance(item.get("digest"), str) else ""
        if not digest and isinstance(item.get("image"), str):
            digest = item["image"]
        stamp = item.get("built_at") if isinstance(item.get("built_at"), str) else ""
        built[key] = ManifestImage(
            service=key,
            built_git_sha=baked,
            digest=digest.strip(),
            built_at=stamp.strip(),
        )
    if not saw_bake:
        return None
    return built


def select_built_images(
    documents: list[object],
    sha: str,
) -> dict[str, ManifestImage] | None:
    """First document in ``documents`` that is the manifest for ``sha``."""

    for document in documents:
        found = images_built_in_manifest(document, sha)
        if found is not None:
            return found
    return None


def _manifest_digest(value: str) -> str:
    text = value.strip().lower()
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", text):
        return text
    return ""


def _manifest_stamp(value: str) -> str:
    text = value.strip()
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text):
        return text
    return ""


def accepts_manifest(
    *,
    git_sha: object,
    built_at: object = "",
    image_digest: object = "",
    expected: str,
    manifest: ManifestImage | None,
) -> bool:
    """True when the process is the image the manifest published."""

    reported = _sha(git_sha)
    want = _sha(expected)
    if not reported:
        return False
    allowed = {sha for sha in (want, manifest.built_git_sha if manifest else "") if sha}
    if reported not in allowed:
        return False
    if manifest is None:
        return True
    stamp = _manifest_stamp(built_at if isinstance(built_at, str) else "")
    pinned_stamp = _manifest_stamp(manifest.built_at)
    if pinned_stamp and stamp and stamp != pinned_stamp:
        return False
    return True


def accepts_identity(
    *,
    git_sha: object,
    built_at: object = "",
    image_digest: object = "",
    image_reference: object = "",
    expected: str,
    pin: OwnerPin | None,
    manifest: ManifestImage | None = None,
) -> bool:
    """True for the reviewed owner pin or the deployed manifest image."""

    if image_reference:
        return pin is not None and pin_matches(pin, git_sha=git_sha,
                                              image_reference=image_reference)
    if pin is not None and pin_matches(
        pin,
        git_sha=git_sha,
        built_at=built_at,
        image_digest=image_digest,
    ):
        return True
    return accepts_manifest(
        git_sha=git_sha,
        built_at=built_at,
        image_digest=image_digest,
        expected=expected,
        manifest=manifest,
    )


def versions_still_missing(
    body: object,
    expected: str,
    built: Mapping[str, ManifestImage],
    pins: Mapping[str, OwnerPin],
) -> frozenset[str]:
    """Built images whose ``/versions`` row is neither the manifest nor its pin."""

    found: set[str] = set()
    rows = body.get("services") if isinstance(body, dict) else None
    if isinstance(rows, list):
        for item in rows:
            if not isinstance(item, dict):
                continue
            name = item.get("service")
            if not isinstance(name, str):
                continue
            key = image_key(name.strip())
            if key not in built:
                continue
            if accepts_identity(
                git_sha=item.get("git_sha"),
                built_at=item.get("built_at", ""),
                image_digest=item.get("image_digest", ""),
                image_reference=item.get("image_reference", ""),
                expected=expected,
                pin=lookup_pin(pins, key),
                manifest=built.get(key),
            ):
                found.add(key)
    return frozenset(built.keys() - found)


def deployed_revision(headers: object) -> str:
    if not isinstance(headers, Mapping):
        return ""
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if key.lower() != REVISION_HEADER:
            continue
        return _sha(value.split(";", 1)[0])
    return ""


def _probe(client: PlaneCall, path: str) -> tuple[int, str, object]:
    try:
        status, headers, body = client("GET", path)
    except (OSError, TimeoutError, ValueError):
        return 0, "", None
    if not isinstance(status, int):
        return 0, "", None
    return status, deployed_revision(headers), body


def wait_rollout(
    client: PlaneCall,
    *,
    expected: str,
    pins: Mapping[str, OwnerPin],
    built: Mapping[str, ManifestImage] | None,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    deadline_s: float,
    poll_s: float = ROLLOUT_POLL_S,
) -> RolloutResult:
    """Wait until the ready header and built images match a pin or the manifest.

    ``built`` None means the manifest could not be read, so only the ready
    header is required. An empty mapping means no image was built at
    ``expected``. A non-200 from any other revision keeps waiting. A
    non-200 from the expected revision or from the hypermesh owner pin
    fails at once.
    """

    want = _sha(expected)
    carried = bool(want) and built is not None and len(built) == 0
    if carried:
        want_header = ""
    else:
        want_header = want
    hypermesh = lookup_pin(pins, "hypermesh-service") if want_header else None
    started = monotonic()
    while True:
        status, deployed, _body = _probe(client, READY_PATH)
        if status <= 0:
            status = 0
            deployed = ""
        elapsed = monotonic() - started
        accepted = bool(want_header) and accepts_identity(
            git_sha=deployed,
            expected=want_header,
            pin=hypermesh,
            manifest=None if built is None else built.get("hypermesh-service"),
        )
        if accepted and status != 200:
            return RolloutResult(
                status="fail",
                detail=f"HTTP {status} from deployed revision {deployed}",
                deployed=deployed,
                expected=want,
                elapsed_s=elapsed,
                http_status=status,
            )
        missing: frozenset[str] = frozenset()
        versions_ok = True
        if want_header and built and status == 200 and accepted:
            version_status, _version_deployed, version_body = _probe(client, VERSIONS_PATH)
            if version_status != 200:
                versions_ok = False
                missing = frozenset(built)
            else:
                missing = versions_still_missing(version_body, want_header, built, pins)
                versions_ok = not missing
        if status == 200 and (not want_header or accepted) and versions_ok:
            if want_header and deployed == want_header:
                detail = f"deployed revision {deployed} == expected {want_header}"
            elif want_header and hypermesh is not None and _sha(deployed) == hypermesh.source_sha:
                detail = f"deployed revision {deployed} is the {hypermesh.repository} test pin"
            elif carried:
                detail = (
                    f"deployed revision {deployed or 'missing'}; no image was built at {want}"
                )
            else:
                detail = f"deployed revision {deployed or 'missing'}"
            return RolloutResult(
                status="pass",
                detail=detail,
                deployed=deployed,
                expected="" if carried or not want else want,
                elapsed_s=elapsed,
                http_status=status,
            )
        if not want_header:
            return RolloutResult(
                status="fail",
                detail=f"HTTP {status}",
                deployed=deployed,
                expected="" if carried else want,
                elapsed_s=elapsed,
                http_status=status,
            )
        if elapsed >= deadline_s:
            if status == 200 and accepted and missing:
                names = ", ".join(sorted(missing))
                detail = (
                    f"rollout not observed: /versions missing {names} "
                    f"at {want_header} after {_format_seconds(elapsed)}s"
                )
            elif status != 200:
                shown = "unavailable" if status == 0 else str(status)
                if deployed:
                    detail = (
                        f"rollout not observed: deployed revision {deployed} != expected "
                        f"{want_header} after {_format_seconds(elapsed)}s; last HTTP {shown}"
                    )
                else:
                    detail = (
                        f"rollout not observed: last HTTP {shown} after "
                        f"{_format_seconds(elapsed)}s (expected {want_header})"
                    )
            else:
                shown = deployed or "missing"
                detail = (
                    f"rollout not observed: deployed revision {shown} != expected "
                    f"{want_header} after {_format_seconds(elapsed)}s"
                )
            return RolloutResult(
                status="fail",
                detail=detail,
                deployed=deployed,
                expected=want,
                elapsed_s=elapsed,
                http_status=status,
                missing=tuple(sorted(missing)),
            )
        sleep(min(poll_s, max(0.0, deadline_s - elapsed)))


def fleet_repository() -> str:
    raw = os.environ.get("HYPERMESH_SMOKE_FLEET_REPOSITORY", FLEET_REPOSITORY).strip()
    return raw if _REPO.fullmatch(raw) else ""


def _github_token() -> str:
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()


def _github_get(url: str, token: str, timeout: float) -> object | None:
    if not token or not url.startswith(_GITHUB_API):
        return None
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.raw" if "/contents/" in url else "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "hypermesh-gateway-smoke",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    if len(raw) > 2 * 1024 * 1024:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None


def built_images_for_revision(
    sha: str,
    *,
    repo: str,
    token: str,
    timeout: float = 15.0,
    getter: Callable[[str], object | None] | None = None,
) -> dict[str, ManifestImage] | None:
    """Manifest rows built at ``sha``. None when the manifest cannot be read."""

    want = _sha(sha)
    if not want or not repo or not _REPO.fullmatch(repo):
        return None

    def fetch(url: str) -> object | None:
        if getter is not None:
            return getter(url)
        return _github_get(url, token, timeout)

    if getter is None and not token:
        return None
    tip_query = urllib.parse.urlencode({"ref": MANIFEST_BRANCH})
    tip_url = f"https://api.github.com/repos/{repo}/contents/{MANIFEST_PATH}?{tip_query}"
    documents: list[object] = []
    tip = fetch(tip_url)
    if isinstance(tip, dict):
        documents.append(tip)
        found = images_built_in_manifest(tip, want)
        if found is not None:
            return found
    query = urllib.parse.urlencode({"sha": MANIFEST_BRANCH, "per_page": str(MANIFEST_LOOKBACK)})
    listing = fetch(f"https://api.github.com/repos/{repo}/commits?{query}")
    if not isinstance(listing, list):
        return select_built_images(documents, want)
    start = 1 if documents else 0
    for item in listing[start:MANIFEST_LOOKBACK]:
        if not isinstance(item, dict):
            continue
        commit_sha = _sha(item.get("sha"))
        if not commit_sha:
            continue
        document = fetch(
            f"https://api.github.com/repos/{repo}/contents/{MANIFEST_PATH}?ref={commit_sha}"
        )
        if not isinstance(document, dict):
            return None
        documents.append(document)
        found = images_built_in_manifest(document, want)
        if found is not None:
            return found
    return select_built_images(documents, want)


class UrllibPlane:
    """GET the public test plane. No credentials are attached."""

    def __init__(self, base: str, timeout: float = 15.0) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout

    def __call__(self, method: str, path: str) -> tuple[int, Mapping[str, str], object]:
        if method != "GET" or not path.startswith("/"):
            raise ValueError(f"unsupported plane call {method} {path}")
        request = urllib.request.Request(
            self.base + path,
            headers={"Accept": "application/json", "User-Agent": "hypermesh-gateway-smoke"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                headers = {key.lower(): value for key, value in response.headers.items()}
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(2 * 1024 * 1024 + 1)
            headers = {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {}
            status = exc.code
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("plane response exceeds 2 MiB")
        body: object
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeError, json.JSONDecodeError):
            body = None
        return status, headers, body


def check_rollout(
    client: PlaneCall,
    *,
    expected: str,
    pins: Mapping[str, OwnerPin],
    built: Mapping[str, ManifestImage] | None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    deadline_s: float | None = None,
) -> RolloutResult:
    return wait_rollout(
        client,
        expected=expected,
        pins=pins,
        built=built,
        sleep=sleep,
        monotonic=monotonic,
        deadline_s=ROLLOUT_WAIT_S if deadline_s is None else deadline_s,
    )


def write_evidence(path: Path, result: RolloutResult, *, pin_origin: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "check": "gateway-post-deploy-rollout",
        "status": result.status,
        "detail": result.detail,
        "deployed_revision": result.deployed,
        "expected_revision": result.expected,
        "http_status": result.http_status,
        "elapsed_s": round(result.elapsed_s, 3),
        "missing": list(result.missing),
        "pin_origin": pin_origin,
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--api-base", default=os.environ.get("HYPERMESH_SMOKE_API_BASE", API_BASE))
    args = parser.parse_args(argv)
    try:
        expected = expected_revision()
    except RevisionError as exc:
        result = RolloutResult(
            status="fail",
            detail=str(exc),
            deployed="",
            expected=exc.requested,
            elapsed_s=0.0,
            http_status=0,
        )
        write_evidence(args.evidence_dir / "gateway-rollout.json", result, pin_origin="not_loaded")
        print(result.detail, file=sys.stderr)
        return 1
    pins, origin = load_owner_pins_from()
    repo = fleet_repository()
    token = _github_token()
    built: Mapping[str, ManifestImage] | None = None
    if expected:
        built = built_images_for_revision(expected, repo=repo, token=token)
    result = check_rollout(
        UrllibPlane(args.api_base),
        expected=expected,
        pins=pins,
        built=built,
        deadline_s=rollout_wait_s(),
    )
    write_evidence(args.evidence_dir / "gateway-rollout.json", result, pin_origin=origin)
    print(result.detail)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
