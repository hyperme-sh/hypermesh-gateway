"""Owner-pin parsing for the gateway post-deploy smoke. No live GitHub or test plane."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "hypermesh-gateway-smoke.yml"
PIN_FILE = ROOT / ".github" / "workflows" / "gateway-owner-pins.json"


def _load():
    path = ROOT / "scripts" / "gateway_owner_pins.py"
    spec = importlib.util.spec_from_file_location("gateway_owner_pins", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


owners = _load()


def test_snapshot_sits_beside_the_workflow_and_names_the_pins() -> None:
    assert PIN_FILE.parent == WORKFLOW.parent
    assert owners.SNAPSHOT_PATH == PIN_FILE
    pins = owners.load_snapshot()
    hypermesh = pins["hypermesh-service"]
    payment = pins["payment-service"]
    gateway = pins["hypermesh-gateway"]
    assert hypermesh.repository == "hyperme-sh/hypermesh-plane"
    assert hypermesh.source_sha == "a6f4c2fd1bb447072fc8321a283037b12be483e3"
    assert hypermesh.built_at == "2026-11-05T16:13:35Z"
    assert payment.repository == "hyperme-sh/payment-service"
    assert payment.source_sha == "da3ca7d4cc8541747835ff06ce1a2e66e3f2299a"
    assert gateway.repository == "hyperme-sh/hypermesh-gateway"
    assert gateway.source_sha == "e6b6a4662cfdcd975ff9d4820b565c30545c39cf"
    assert gateway.built_at == "2026-11-05T18:25:22Z"
    assert owners.lookup_pin(pins, "marketplace-service").service == "marketplace"


def test_pin_matches_source_sha_and_rejects_a_disagreeing_stamp() -> None:
    pin = owners.OwnerPin(
        "hypermesh-service",
        "hyperme-sh/hypermesh-plane",
        "a" * 40,
        built_at="2026-11-05T16:13:35Z",
        digest="sha256:" + "ab" * 32,
    )
    assert owners.pin_matches(pin, git_sha="A" * 40, built_at="unknown")
    assert not owners.pin_matches(pin, git_sha="a" * 40, built_at="2026-11-05T18:25:22Z")
    assert owners.pin_matches(pin, git_sha="a" * 40, image_digest="sha256:" + "cd" * 32)
    assert not owners.pin_matches(pin, git_sha="b" * 40)


def test_runtime_document_overlays_the_candidate_sha() -> None:
    candidates = {
        "services": {
            "hypermesh-service": {
                "repository": "hyperme-sh/hypermesh-plane",
                "source_sha": "c" * 40,
                "compose_service": "hypermesh-service",
            }
        }
    }
    runtime = {
        "services": {
            "hypermesh-service": {
                "repository": "hyperme-sh/hypermesh-plane",
                "source_sha": "d" * 40,
                "built_at": "2026-11-05T16:13:35Z",
            }
        }
    }
    merged = owners.merge_pins(
        owners.pins_from_document(candidates),
        owners.pins_from_document(runtime),
    )
    assert merged["hypermesh-service"].source_sha == "d" * 40
    assert merged["hypermesh-service"].built_at == "2026-11-05T16:13:35Z"


def test_gateway_document_is_a_single_service() -> None:
    pins = owners.pins_from_document(
        {
            "service": {
                "repository": "hyperme-sh/hypermesh-gateway",
                "source_sha": "e" * 40,
                "built_at": "2026-11-05T18:25:22Z",
                "image": "acrfybercg47.azurecr.io/hypermesh-gateway:test",
                "recorded_image": "acrfybercg47.azurecr.io/hypermesh-gateway@sha256:" + "ab" * 32,
            }
        }
    )
    assert pins["hypermesh-gateway"].source_sha == "e" * 40
    assert pins["hypermesh-gateway"].digest == "sha256:" + "ab" * 32


def test_live_infra_overlay_wins_and_a_failed_read_uses_the_snapshot() -> None:
    runtime_sha = "d" * 40

    def live(url, _token, _timeout, _accept):
        assert url.startswith("https://api.github.com/repos/FyberLabs/infra/contents/")
        assert "ref=heads/main" in url
        if url.endswith("verification-owner-candidates.json?ref=heads/main") or (
            "verification-owner-candidates.json" in url
        ):
            return 200, {
                "services": {
                    "hypermesh-service": {
                        "repository": "hyperme-sh/hypermesh-plane",
                        "source_sha": "c" * 40,
                    }
                }
            }
        if "test-standalone-owners.json" in url:
            return 200, {
                "services": {
                    "hypermesh-service": {
                        "repository": "hyperme-sh/hypermesh-plane",
                        "source_sha": runtime_sha,
                        "built_at": "2026-11-05T16:13:35Z",
                    }
                }
            }
        if "test-standalone-gateway.json" in url:
            return 200, {
                "service": {
                    "repository": "hyperme-sh/hypermesh-gateway",
                    "source_sha": "e" * 40,
                }
            }
        raise AssertionError(url)

    pins, origin = owners.load_owner_pins_from(live, token="token", timeout=1)
    assert origin == "infra"
    assert pins["hypermesh-service"].source_sha == runtime_sha
    assert pins["hypermesh-gateway"].source_sha == "e" * 40

    def denied(*_args):
        return 404, None

    fallback, fallback_origin = owners.load_owner_pins_from(denied, token="token", timeout=1)
    assert fallback_origin == "snapshot"
    assert fallback["hypermesh-service"].source_sha == "a6f4c2fd1bb447072fc8321a283037b12be483e3"


def test_missing_token_does_not_read_infra() -> None:
    def fetch(*_args):
        raise AssertionError("infra was contacted")

    pins, origin = owners.load_owner_pins_from(fetch, token="", timeout=1)
    assert origin == "snapshot"
    assert "payment-service" in pins


def test_infra_read_is_a_get_and_refuses_other_hosts(monkeypatch) -> None:
    seen: dict[str, str] = {}

    def urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        assert timeout == 1
        raise owners.urllib.error.URLError("stop")

    monkeypatch.setattr(owners.urllib.request, "urlopen", urlopen)
    status, body = owners._default_fetch(
        "https://api.github.com/repos/FyberLabs/infra/contents/config/deployments/verification-owner-candidates.json?ref=heads/main",
        "sekret",
        1,
        "application/vnd.github.raw",
    )
    assert (status, body) == (0, None)
    assert seen["method"] == "GET"
    assert seen["url"].startswith("https://api.github.com/repos/FyberLabs/infra/")
    assert "sekret" not in seen["url"]

    def opened(*_args, **_kwargs):
        raise AssertionError("token left GitHub")

    monkeypatch.setattr(owners.urllib.request, "urlopen", opened)
    status, body = owners._default_fetch("https://evil.example/steal", "sekret", 1, "application/json")
    assert (status, body) == (0, None)


def test_broken_snapshot_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "gateway-owner-pins.json"
    path.write_text("{", encoding="utf-8")
    assert owners.load_snapshot(path) == {}
    path.write_text(json.dumps({"services": {"hypermesh-service": {"source_sha": "nope"}}}), encoding="utf-8")
    assert owners.load_snapshot(path) == {}


def test_channel_comparison_ignores_recorded_digest_and_refuses_other_tags():
    pin = owners.OwnerPin("gateway", "hyperme-sh/hypermesh-gateway", "a" * 40,
                          image="ghcr.io/hyperme-sh/hypermesh-gateway/runtime:test")
    assert owners.pin_matches(pin, git_sha="b" * 40, image_reference=pin.image,
                              image_digest="sha256:" + "c" * 64)
    for wrong in (pin.image.replace(":test", ":prod"), pin.image.split(":")[0] + "@sha256:" + "a" * 64):
        assert not owners.pin_matches(pin, git_sha="a" * 40, image_reference=wrong)
    import re
    snapshot = json.loads(PIN_FILE.read_text())
    assert all(re.fullmatch(r"[a-z0-9][a-z0-9./_-]+:test", row["image"]) for row in snapshot["services"].values())
