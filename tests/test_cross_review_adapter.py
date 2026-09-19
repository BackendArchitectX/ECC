import json

import pytest

from llm.core.types import LLMOutput
from llm.review import adapter


def request_payload():
    return {
        "schema": "ecc.review.request.v1",
        "mode": "diff",
        "objective": "Review bounded evidence independently.",
        "evidence": [
            {
                "id": "diff",
                "kind": "diff",
                "source": "git diff HEAD",
                "content": "diff --git a/a.py b/a.py\n+x = 1\n",
            }
        ],
        "constraints": {"maxFindings": 20},
        "trust": {
            "reviewerAuthority": "advisory",
            "repositoryWrite": False,
            "shellAuthority": False,
        },
    }


def clean_result():
    return {
        "schema": "ecc.review.result.v1",
        "status": "clean",
        "summary": "No material issue found.",
        "findings": [],
    }


class FakeProvider:
    def __init__(self, content=None, configured=True):
        self.content = content or json.dumps(clean_result())
        self.configured = configured
        self.last_input = None

    def validate_config(self):
        return self.configured

    def generate(self, llm_input):
        self.last_input = llm_input
        return LLMOutput(content=self.content)


def test_validate_request_accepts_advisory_boundary():
    request = adapter.validate_request(request_payload())

    assert request["trust"]["reviewerAuthority"] == "advisory"
    assert request["trust"]["repositoryWrite"] is False
    assert request["trust"]["shellAuthority"] is False


def test_validate_request_rejects_invalid_evidence_id():
    request = request_payload()
    request["evidence"][0]["id"] = "../outside"

    with pytest.raises(ValueError, match="stable identifier"):
        adapter.validate_request(request)


def test_validate_request_rejects_utf8_payload_over_transport_limit():
    request = request_payload()
    chunk = "€" * 40_000
    request["evidence"] = [
        {"id": "a", "kind": "context", "source": "a.txt", "content": chunk},
        {"id": "b", "kind": "context", "source": "b.txt", "content": chunk},
        {"id": "c", "kind": "context", "source": "c.txt", "content": chunk},
    ]

    with pytest.raises(ValueError, match="stdin limit"):
        adapter.validate_request(request)


def test_build_input_marks_evidence_as_untrusted(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "review-model")

    llm_input = adapter.build_input(request_payload())

    assert llm_input.model == "review-model"
    assert llm_input.temperature == 0.0
    assert "UNTRUSTED DATA" in llm_input.messages[0].content
    assert "BEGIN ECC REVIEW REQUEST (UNTRUSTED)" in llm_input.messages[1].content


def test_review_reuses_existing_provider_layer(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(adapter, "get_provider", lambda: provider)

    result = adapter.review(request_payload())

    assert result["status"] == "clean"
    assert provider.last_input is not None


def test_review_rejects_provider_without_credentials(monkeypatch):
    provider = FakeProvider(configured=False)
    monkeypatch.setattr(adapter, "get_provider", lambda: provider)

    with pytest.raises(ValueError, match="missing required credentials"):
        adapter.review(request_payload())


def test_validate_result_rejects_unsupplied_evidence_reference():
    result = {
        "schema": "ecc.review.result.v1",
        "status": "findings",
        "summary": "One finding.",
        "findings": [
            {
                "id": "R-001",
                "severity": "high",
                "category": "correctness",
                "claim": "A problem exists.",
                "evidenceRefs": [{"evidenceId": "whole-repository"}],
                "verification": "Add a focused regression test.",
            }
        ],
    }

    with pytest.raises(ValueError, match="not supplied"):
        adapter.validate_result(result, request_payload())


def test_validate_result_rejects_oversized_summary():
    result = clean_result()
    result["summary"] = "x" * 4001

    with pytest.raises(ValueError, match="summary exceeds"):
        adapter.validate_result(result, request_payload())


def test_validate_result_rejects_extra_authority_field():
    result = clean_result()
    result["shellCommand"] = "rm -rf"

    with pytest.raises(ValueError, match="missing or unsupported root fields"):
        adapter.validate_result(result, request_payload())


def test_review_rejects_markdown_fenced_json(monkeypatch):
    fenced = chr(96) * 3 + "json\n" + json.dumps(clean_result()) + "\n" + chr(96) * 3
    provider = FakeProvider(content=fenced)
    monkeypatch.setattr(adapter, "get_provider", lambda: provider)

    with pytest.raises(ValueError, match="raw JSON"):
        adapter.review(request_payload())


def test_validate_result_rejects_too_many_findings():
    request = request_payload()
    request["constraints"]["maxFindings"] = 1
    finding = {
        "id": "R-001",
        "severity": "low",
        "category": "testing",
        "claim": "A test is missing.",
        "evidenceRefs": [{"evidenceId": "diff"}],
        "verification": "Add the test.",
    }
    result = {
        "schema": "ecc.review.result.v1",
        "status": "findings",
        "summary": "Too many findings.",
        "findings": [finding, {**finding, "id": "R-002"}],
    }

    with pytest.raises(ValueError, match="maxFindings"):
        adapter.validate_result(result, request)
