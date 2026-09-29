import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from leakscope import __version__
from leakscope.classify.jev import JevClient, JevIntegrationError, JevQuestionSet, validate_answers
from leakscope.detectors import has_placeholder, matching_domains
from leakscope.masking import item_fingerprint, sanitize
from leakscope.models import Evidence, TriageRequest, TriageResult
from leakscope.policy.engine import PolicyEngine


class TriageService:
    def __init__(
        self,
        policy_path: Path | None = None,
        fingerprint_key: bytes | None = None,
        classifier: JevClient | None = None,
    ):
        configured_key = os.getenv("LEAKSCOPE_FINGERPRINT_KEY")
        if fingerprint_key is None and configured_key:
            fingerprint_key = configured_key.encode("utf-8")
        if fingerprint_key is not None and len(fingerprint_key) < 32:
            raise ValueError("Fingerprint key must contain at least 32 bytes")
        self.fingerprint_key = fingerprint_key or secrets.token_bytes(32)
        self.stable_fingerprints = fingerprint_key is not None
        self.domains = {
            domain.strip().lower().lstrip("@.")
            for domain in os.getenv("LEAKSCOPE_ORG_DOMAINS", "").split(",")
            if domain.strip()
        }
        self.policy = PolicyEngine(policy_path) if policy_path else PolicyEngine()
        self.classifier = classifier or JevClient()
        self.questions = JevQuestionSet()

    @staticmethod
    def _age_days(found_at: datetime | None) -> int | None:
        if found_at is None:
            return None
        timestamp = found_at if found_at.tzinfo else found_at.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - timestamp.astimezone(UTC)).days)

    def triage(self, request: TriageRequest) -> TriageResult:
        sanitized = sanitize(request.text, self.fingerprint_key)
        fingerprint = item_fingerprint(request.text, self.fingerprint_key)
        safe_source = sanitize(request.source, self.fingerprint_key).text[:128]
        domains = matching_domains(sanitized.text, self.domains)
        age_days = self._age_days(request.found_at)
        facts: dict[str, Any] = {
            "detected_types": sorted({match.kind for match in sanitized.matches}),
            "secret_present": bool(sanitized.matches),
            "placeholder": has_placeholder(sanitized.text) and not sanitized.matches,
            "canary_match": False,
            "owned_domain_match": bool(domains),
            "matched_domains": domains,
            "truncated": sanitized.truncated,
            "evidence_truncated": len(sanitized.matches) > 100,
            "age_days": age_days,
            "classifier_available": self.classifier.configured,
        }
        candidates = [fingerprint, *sanitized.fingerprints]
        canary_fingerprints = [
            os.getenv(f"LEAKESCOPE_CANARY_FINGERPRINT_{index}", "")
            for index in range(32)
        ]
        facts["canary_match"] = any(
            expected and secrets.compare_digest(expected, candidate)
            for expected in canary_fingerprints
            for candidate in candidates
        )
        answers: dict[str, Any] = {}
        model_id = "not-configured"
        deterministic_only = facts["placeholder"] or sanitized.truncated or facts["canary_match"]
        if not deterministic_only and self.classifier.configured:
            state = {
                "item": sanitized.text,
                "source": {"type": safe_source, "age_days": age_days},
                "facts": {
                    "detected_types": facts["detected_types"],
                    "secret_present": facts["secret_present"],
                    "placeholder": facts["placeholder"],
                    "canary_match": facts["canary_match"],
                    "owned_domain_match": facts["owned_domain_match"],
                },
                "org": {"owned_domain_match": facts["owned_domain_match"]},
            }
            try:
                raw_answers: dict[str, Any] = {}
                for batch in self.questions.batches():
                    response = self.classifier.evaluate(state, batch)
                    model_id = response["model"]
                    raw_answers.update(response["answers"])
                answers = validate_answers(self.questions, raw_answers)
                if facts["owned_domain_match"]:
                    answers["ours"] = {"type": "noul", "noul": 1.0}
                    answers["ours_twin"] = {"type": "noul", "noul": 1.0}
            except JevIntegrationError:
                facts["classifier_available"] = False

        model_status = (
            "skipped"
            if deterministic_only
            else "configured"
            if answers
            else "unavailable"
            if not self.classifier.configured
            else "error"
        )
        facts["model_status"] = model_status
        facts["answers"] = answers
        level, reasons = self.policy.decide(facts)
        if facts["placeholder"]:
            reasons = ["Placeholder or example content; no supported secret detected"]
        evidence = [
            Evidence(
                kind=match.kind,
                masked=f"[REDACTED:{match.kind}]",
                structural_valid=match.structural_valid,
                is_test_value=match.is_test_value,
            )
            for match in sanitized.matches
        ]
        return TriageResult(
            item_id=f"lk_{fingerprint[:20]}",
            source=safe_source,
            found_at=request.found_at,
            level=level,
            reasons=reasons,
            masked_text=sanitized.text,
            evidence=evidence[:100],
            facts=facts,
            answers=answers,
            model_status=model_status,
            provenance={
                "model": model_id,
                "questions": self.questions.version,
                "policy": str(self.policy.config["version"]),
                "fingerprint": f"hmac-sha256:{fingerprint}",
                "engine": __version__,
                "fingerprint_stable": str(self.stable_fingerprints).lower(),
            },
        )
