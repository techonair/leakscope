import base64
import json

from fastapi.testclient import TestClient

from leakscope.api import app
from leakscope.models import TriageRequest
from leakscope.service import TriageService


def _jwt() -> str:
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{encode({'alg': 'none'})}.{encode({'sub': 'demo'})}.signature"


def test_aws_secret_is_masked_and_needs_review() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = TriageService(fingerprint_key=b"x" * 32).triage(TriageRequest(text=f"key={secret}"))
    serialized = result.model_dump_json()
    assert secret not in serialized
    assert result.level == "REVIEW"
    assert result.evidence[0].kind == "aws_access_key"
    assert "[REDACTED:aws_access_key]" in result.masked_text


def test_placeholder_is_suppressed() -> None:
    result = TriageService(fingerprint_key=b"x" * 32).triage(TriageRequest(text="api_key=changeme"))
    assert result.level == "L0"
    assert not result.evidence


def test_jwt_is_detected_but_not_verified() -> None:
    result = TriageService(fingerprint_key=b"x" * 32).triage(TriageRequest(text=f"token={_jwt()}"))
    assert result.evidence[0].kind == "jwt"
    assert result.evidence[0].structural_valid is True
    assert result.level == "REVIEW"


def test_test_card_is_flagged_as_test_data() -> None:
    result = TriageService(fingerprint_key=b"x" * 32).triage(TriageRequest(text="4111 1111 1111 1111"))
    assert result.evidence[0].is_test_value


def test_api_response_never_contains_raw_secret() -> None:
    client = TestClient(app)
    secret = "ghp_" + "A" * 36
    response = client.post("/v1/triage", json={"text": f"token={secret}"})
    assert response.status_code == 200
    assert secret not in response.text
    assert response.json()["level"] == "REVIEW"


def test_zero_width_characters_are_removed() -> None:
    result = TriageService(fingerprint_key=b"x" * 32).triage(
        TriageRequest(text="AKIAIOSFODNN7EXAMPLE\u200b")
    )
    assert result.evidence[0].kind == "aws_access_key"


def test_plaintext_canary_match_escalates(monkeypatch) -> None:
    from leakscope.masking import item_fingerprint

    key = b"x" * 32
    canary = "leakscope-owned-honeytoken"
    monkeypatch.setenv("LEAKESCOPE_CANARY_FINGERPRINT_0", item_fingerprint(canary, key))
    result = TriageService(fingerprint_key=key).triage(TriageRequest(text=canary))
    assert result.level == "L4"
    assert result.facts["canary_match"] is True


def test_truncated_input_does_not_return_partial_secret() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = TriageService(fingerprint_key=b"x" * 32).triage(
        TriageRequest(text=(" " * 11_990) + secret + (" " * 100))
    )
    assert result.facts["truncated"] is True
    assert secret not in result.masked_text
    assert result.masked_text == "[TRUNCATED: preview omitted]"
    assert result.evidence[0].kind == "aws_access_key"


def test_invalid_request_does_not_echo_raw_input() -> None:
    client = TestClient(app)
    secret = "ghp_" + "A" * 36
    response = client.post("/v1/triage", json={"text": secret, "source": "x" * 129})
    assert response.status_code == 422
    assert secret not in response.text


def test_local_analyst_console_is_served() -> None:
    client = TestClient(app)
    page = client.get("/")
    script = client.get("/assets/app.js")
    assert page.status_code == 200
    assert "Triage an alert" in page.text
    assert script.status_code == 200
    assert "v1/triage" in script.text
