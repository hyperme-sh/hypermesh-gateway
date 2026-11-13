"""Gateway post-deploy rollout identity. No live GitHub, deploy, or test plane."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "hypermesh-gateway-smoke.yml"


def _load(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


owners = _load("gateway_owner_pins")
smoke = _load("gateway_post_deploy_smoke")

DEPLOYED = "7f2dc527fed23af08262eb802de9fe8a2539d564"
EXPECTED = "5836c361360038ce94f4f7139ca6dd1e8a412920"
PAYMENT = "da3ca7d4cc8541747835ff06ce1a2e66e3f2299a"
HYPERMESH_PIN = "a6f4c2fd1bb447072fc8321a283037b12be483e3"


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept = 0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept += 1
        self.now += seconds


class ScriptedPlane:
    def __init__(self, responses: list[tuple[int, dict[str, str], object]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method: str, path: str) -> tuple[int, dict[str, str], object]:
        self.calls.append((method, path))
        if not self.responses:
            raise AssertionError(f"unexpected {method} {path}")
        return self.responses.pop(0)


def _pins() -> dict:
    return {
        "hypermesh-service": owners.OwnerPin(
            "hypermesh-service",
            "hyperme-sh/hypermesh-plane",
            DEPLOYED,
        ),
        "payment-service": owners.OwnerPin(
            "payment-service",
            "hyperme-sh/payment-service",
            PAYMENT,
            digest="sha256:" + "ab" * 32,
        ),
    }


def _built_payment() -> dict:
    return {
        "payment-service": smoke.ManifestImage(
            "payment-service",
            EXPECTED,
            digest="sha256:" + "cd" * 32,
        )
    }


def test_workflow_dispatches_only_from_main_and_keeps_the_pin_beside_it() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "\n  push:" not in text
    assert "refs/heads/main" in text
    assert "contents: read" in text
    assert "contents: write" not in text
    assert "gateway_post_deploy_smoke.py" in text
    assert "gateway-owner-pins.json" in text
    assert "actions/checkout@" in text
    assert "FyberLabs/infra" not in text[text.index("jobs:"):]
    assert owners.SNAPSHOT_PATH == WORKFLOW.parent / "gateway-owner-pins.json"


def test_manifest_lists_images_built_at_the_sha_and_skips_a_carried_publish() -> None:
    carried = "a" * 40
    document = {
        "git_sha": EXPECTED,
        "services": [
            {"service": "payment-service", "built_git_sha": EXPECTED, "digest": "sha256:" + "cd" * 32},
            {"service": "hypermesh-service", "built_git_sha": carried},
            {"service": "marketplace-service", "built_git_sha": EXPECTED},
        ],
    }
    built = smoke.images_built_in_manifest(document, EXPECTED)
    assert built is not None
    assert set(built) == {"payment-service", "marketplace"}
    assert built["payment-service"].digest == "sha256:" + "cd" * 32
    carried_document = {
        "git_sha": EXPECTED,
        "services": [{"service": "payment-service", "built_git_sha": carried}],
    }
    assert smoke.images_built_in_manifest(carried_document, EXPECTED) == {}
    assert smoke.images_built_in_manifest({"git_sha": "b" * 40, "services": []}, EXPECTED) is None
    assert smoke.select_built_images(
        [{"git_sha": "b" * 40, "services": [{"service": "payment-service", "built_git_sha": "b" * 40}]}, document],
        EXPECTED,
    ) == built


def test_rollout_accepts_the_reviewed_owner_pins_after_a_rebuild() -> None:
    """Panopticon rebuilt payment; the plane is the owner images, not that sha."""

    clock = Clock()
    plane = ScriptedPlane(
        [
            (200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}),
            (200, {}, {"services": [{"service": "payment-service", "git_sha": PAYMENT}]}),
        ]
    )
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        deadline_s=600,
    )
    assert result.status == "pass"
    assert result.detail == f"deployed revision {DEPLOYED} is the hyperme-sh/hypermesh-plane test pin"
    assert result.deployed == DEPLOYED
    assert result.expected == EXPECTED
    assert plane.calls == [("GET", "/api/v1/hypermesh/ready"), ("GET", "/versions")]
    assert clock.slept == 0


def test_rollout_accepts_the_deployed_manifest_without_a_pin() -> None:
    clock = Clock()
    plane = ScriptedPlane(
        [
            (200, {"X-Hypermesh-Revision": EXPECTED}, {"status": "ok"}),
            (
                200,
                {},
                {
                    "services": [
                        {
                            "service": "payment-service",
                            "git_sha": EXPECTED,
                            "image_digest": "sha256:" + "cd" * 32,
                        }
                    ]
                },
            ),
        ]
    )
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins={},
        built=_built_payment(),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        deadline_s=600,
    )
    assert result.status == "pass"
    assert result.detail == f"deployed revision {EXPECTED} == expected {EXPECTED}"


def test_rollout_fails_an_unpinned_wrong_sha() -> None:
    stranger = "ab" * 20
    clock = Clock()
    plane = ScriptedPlane(
        [
            (200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}),
            (200, {}, {"services": [{"service": "payment-service", "git_sha": stranger}]}),
            (200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}),
            (200, {}, {"services": [{"service": "payment-service", "git_sha": stranger}]}),
        ]
    )
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        deadline_s=10,
    )
    assert result.status == "fail"
    assert result.missing == ("payment-service",)
    assert "payment-service" in result.detail
    assert ("GET", "/api/v1/hypermesh/leases") not in plane.calls


def test_header_stranger_fails_when_it_matches_neither_pin_nor_manifest() -> None:
    stranger = "cd" * 20
    plane = ScriptedPlane([(200, {"x-hypermesh-revision": stranger}, {"status": "ok"})])
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=Clock().sleep,
        monotonic=Clock().monotonic,
        deadline_s=0,
    )
    assert result.status == "fail"
    assert stranger in result.detail
    assert len(plane.calls) == 1


def test_recorded_digest_does_not_block_the_requested_revision_diagnostic() -> None:
    plane = ScriptedPlane(
        [
            (200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}),
            (
                200,
                {},
                {
                    "services": [
                        {
                            "service": "payment-service",
                            "git_sha": PAYMENT,
                            "image_digest": "sha256:" + "ef" * 32,
                        }
                    ]
                },
            ),
        ]
    )
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=Clock().sleep,
        monotonic=Clock().monotonic,
        deadline_s=0,
    )
    assert result.status == "pass"
    assert result.missing == ()


def test_manifest_digest_matches_when_the_pin_digest_does_not() -> None:
    observed = {
        "git_sha": EXPECTED,
        "built_at": "",
        "image_digest": "sha256:" + "cd" * 32,
    }
    pin = owners.OwnerPin(
        "payment-service",
        "hyperme-sh/payment-service",
        EXPECTED,
        digest="sha256:" + "ab" * 32,
    )
    manifest = smoke.ManifestImage("payment-service", EXPECTED, digest="sha256:" + "cd" * 32)
    assert owners.pin_matches(pin, git_sha=EXPECTED, image_digest=observed["image_digest"])
    assert smoke.accepts_identity(
        git_sha=observed["git_sha"],
        image_digest=observed["image_digest"],
        expected=EXPECTED,
        pin=pin,
        manifest=manifest,
    )


def test_non_200_from_the_owner_pin_fails_immediately() -> None:
    plane = ScriptedPlane([(503, {"x-hypermesh-revision": DEPLOYED}, None)])
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=Clock().sleep,
        monotonic=Clock().monotonic,
        deadline_s=600,
    )
    assert result.status == "fail"
    assert result.detail == f"HTTP 503 from deployed revision {DEPLOYED}"
    assert len(plane.calls) == 1


def test_old_revision_keeps_waiting_until_the_pin_is_served() -> None:
    clock = Clock()
    plane = ScriptedPlane(
        [
            (502, {"x-hypermesh-revision": HYPERMESH_PIN}, None),
            (200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}),
            (200, {}, {"services": [{"service": "payment-service", "git_sha": PAYMENT}]}),
        ]
    )
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        deadline_s=600,
    )
    assert result.status == "pass"
    assert clock.slept == 1


def test_carried_manifest_records_the_deployed_header() -> None:
    plane = ScriptedPlane([(200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"})])
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built={},
        sleep=Clock().sleep,
        monotonic=Clock().monotonic,
        deadline_s=600,
    )
    assert result.status == "pass"
    assert result.detail == f"deployed revision {DEPLOYED}; no image was built at {EXPECTED}"
    assert result.expected == ""
    assert plane.calls == [("GET", "/api/v1/hypermesh/ready")]


def test_transport_failure_keeps_waiting() -> None:
    clock = Clock()

    class Flaky:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def __call__(self, method: str, path: str):
            self.calls.append((method, path))
            if len(self.calls) == 1:
                raise OSError("unreachable")
            if path == smoke.READY_PATH:
                return 200, {"x-hypermesh-revision": DEPLOYED}, {"status": "ok"}
            return 200, {}, {"services": [{"service": "payment-service", "git_sha": PAYMENT}]}

    plane = Flaky()
    result = smoke.wait_rollout(
        plane,
        expected=EXPECTED,
        pins=_pins(),
        built=_built_payment(),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        deadline_s=600,
    )
    assert result.status == "pass"
    assert clock.slept == 1
    assert ("GET", "/api/v1/hypermesh/leases") not in plane.calls


def test_plane_read_sends_no_credential(monkeypatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        status = 200
        headers = {"x-hypermesh-revision": DEPLOYED}

        def read(self, _limit: int) -> bytes:
            return b'{"status":"ok"}'

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> bool:
            return False

    def urlopen(request, timeout):
        seen["method"] = request.get_method()
        seen["url"] = request.full_url
        seen["headers"] = {key.lower(): value for key, value in request.header_items()}
        assert timeout == 15.0
        return Response()

    monkeypatch.setattr(smoke.urllib.request, "urlopen", urlopen)
    status, headers, body = smoke.UrllibPlane("https://api.test.hyperme.sh")("GET", smoke.READY_PATH)
    assert status == 200
    assert body == {"status": "ok"}
    assert headers["x-hypermesh-revision"] == DEPLOYED
    assert seen["method"] == "GET"
    assert seen["url"] == "https://api.test.hyperme.sh/api/v1/hypermesh/ready"
    assert "authorization" not in seen["headers"]
    try:
        smoke.UrllibPlane("https://api.test.hyperme.sh")("POST", smoke.READY_PATH)
    except ValueError as exc:
        assert "POST" in str(exc)
    else:
        raise AssertionError("plane client accepted a write")


def test_manifest_fetch_stays_on_github(monkeypatch) -> None:
    def urlopen(*_args, **_kwargs):
        raise AssertionError("opened")

    monkeypatch.setattr(smoke.urllib.request, "urlopen", urlopen)
    assert smoke._github_get("https://evil.example/image-manifest.json", "sekret", 1) is None


def test_blank_expected_revision_is_record_only(monkeypatch: pytest.MonkeyPatch) -> None:
    assert smoke.expected_revision("") == ""
    assert smoke.expected_revision("   ") == ""
    monkeypatch.delenv("HYPERMESH_SMOKE_EXPECT_REVISION", raising=False)
    assert smoke.expected_revision() == ""
    monkeypatch.setenv("HYPERMESH_SMOKE_EXPECT_REVISION", "  ")
    assert smoke.expected_revision() == ""
    assert smoke.expected_revision("A" * 40) == "a" * 40


def test_abbreviated_expected_revision_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HYPERMESH_SMOKE_EXPECT_REVISION", "  01d293e  ")

    def opened(*_args, **_kwargs):
        raise AssertionError("network")

    monkeypatch.setattr(smoke.urllib.request, "urlopen", opened)
    monkeypatch.setattr(smoke, "load_owner_pins_from", opened)
    monkeypatch.setattr(smoke, "check_rollout", opened)
    code = smoke.main(["--evidence-dir", str(tmp_path)])
    document = json.loads((tmp_path / "gateway-rollout.json").read_text(encoding="utf-8"))
    assert code == 1
    assert document["status"] == "fail"
    assert document["expected_revision"] == "01d293e"
    assert document["deployed_revision"] == ""
    assert document["pin_origin"] == "not_loaded"
    assert "01d293e" in document["detail"]
    with pytest.raises(smoke.RevisionError):
        smoke.expected_revision("zzzz" + "a" * 36)


def test_snapshot_pin_accepts_the_recorded_hypermesh_sha() -> None:
    pins = owners.load_snapshot()
    assert smoke.accepts_identity(
        git_sha=HYPERMESH_PIN,
        built_at="unknown",
        expected=EXPECTED,
        pin=owners.lookup_pin(pins, "hypermesh-service"),
    )
    assert not smoke.accepts_identity(
        git_sha="ee" * 20,
        expected=EXPECTED,
        pin=owners.lookup_pin(pins, "hypermesh-service"),
    )


def test_reported_wrong_channel_cannot_fall_back_to_matching_revision():
    pin = owners.OwnerPin("payment-service", "hyperme-sh/payment-service", EXPECTED,
                          image="ghcr.io/hyperme-sh/payment-service/runtime:test")
    assert smoke.accepts_identity(git_sha="f" * 40, expected=EXPECTED, pin=pin,
                                  image_reference=pin.image)
    assert not smoke.accepts_identity(git_sha=EXPECTED, expected=EXPECTED, pin=pin,
                                      image_reference=pin.image.replace(":test", ":prod"))
