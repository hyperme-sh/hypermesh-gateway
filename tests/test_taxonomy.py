from __future__ import annotations

import json
import logging
from pathlib import Path

from hypermesh_gateway_service.classify import (
    CLASS_OUT_OF_SCOPE,
    CLASS_POLICY_REVIEW,
    resolve_classifier,
)
from hypermesh_gateway_service.taxonomy import (
    ClosedClassifier,
    TaxonomyPackClassifier,
    bundled_pack_path,
    load_taxonomy_pack,
    match_node,
    normalize_prompt,
)

FIXTURE_PACK = Path(__file__).parent / "fixtures" / "ir-taxonomy-fixture.json"


def test_bundled_pack_is_versioned_json_on_disk():
    path = bundled_pack_path()
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == "ir-taxonomy-v1"
    assert "detector" in payload["description"].lower() or "casb" in payload["description"].lower()
    ids = {item["id"] for item in payload["classes"]}
    assert ids == {
        "incident_triage",
        "vuln_review",
        "malware_analysis",
        "policy_review",
        "out_of_scope",
    }


def test_fixture_pack_allow_vs_hold_without_live_model():
    classifier = TaxonomyPackClassifier.from_path(FIXTURE_PACK)
    assert classifier.pack_version == "ir-taxonomy-fixture"
    allowed = classifier.classify("Need a SOC control mapping for the new policy.")
    assert allowed.decision == "allow"
    assert allowed.prompt_class == CLASS_POLICY_REVIEW
    assert allowed.rule_id == "allow.fixture_policy"
    held = classifier.classify("Triage this SIEM alert and list containment steps.")
    assert held.decision == "hold"
    assert held.prompt_class == CLASS_OUT_OF_SCOPE
    assert held.pack_version == "ir-taxonomy-fixture"


def test_resolve_classifier_override_and_closed_on_bad_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("HYPERMESH_IR_TAXONOMY_PACK", str(FIXTURE_PACK))
    from_env = resolve_classifier()
    assert from_env.pack_version == "ir-taxonomy-fixture"
    monkeypatch.delenv("HYPERMESH_IR_TAXONOMY_PACK", raising=False)
    from_file = resolve_classifier(FIXTURE_PACK)
    assert from_file.pack_version == "ir-taxonomy-fixture"
    missing = resolve_classifier(tmp_path / "no-such-pack.json")
    assert isinstance(missing, ClosedClassifier)
    assert missing.classify("CVE-2024-1234").decision == "hold"
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert resolve_classifier(broken).classify("anything").decision == "hold"


def test_matchers_are_structured_not_raw_keyword_scan():
    blob = normalize_prompt("Review the finding from last week's scan.")
    assert match_node({"all": [{"token": "finding"}, {"token": "review"}]}, blob)
    assert not match_node({"phrase": "finding review"}, blob)
    assert match_node({"regex": r"\bcve-\d{4}-\d+\b"}, "see CVE-2024-1234 please")
    assert not match_node({"regex": r"\bcve-\d{4}-\d+\b"}, "scve-not")
    assert match_node({"not": {"token": "jailbreak"}}, "incident triage")
    assert not match_node({"all": []}, blob)
    assert not match_node("bare", blob)


def test_invalid_pack_rejected():
    try:
        load_taxonomy_pack({"version": "", "default": {"class": "out_of_scope", "disposition": "hold"}})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("empty version must fail")
    try:
        load_taxonomy_pack(
            {
                "version": "x",
                "default": {"class": "out_of_scope", "disposition": "hold"},
                "classes": [{"id": "out_of_scope", "disposition": "hold"}],
                "rules": [{"id": "r", "class": "missing", "match": {"phrase": "x"}}],
            }
        )
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unknown class must fail")


def test_classify_does_not_log_prompt_bodies(caplog):
    prompt = "secret prompt body must never appear in logs"
    with caplog.at_level(logging.INFO, logger="hypermesh_gateway_service"):
        TaxonomyPackClassifier.from_bundled().classify(prompt)
    blob = caplog.text
    assert prompt not in blob
    assert "secret prompt" not in blob
