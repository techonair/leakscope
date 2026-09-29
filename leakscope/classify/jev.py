import math
import os
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

DEFAULT_QUESTIONS = Path(__file__).resolve().with_name("v1.yaml")
if not DEFAULT_QUESTIONS.exists():
    DEFAULT_QUESTIONS = Path(__file__).resolve().parents[2] / "questions" / "v1.yaml"

JEV_ENDPOINT = "https://thejevai.com/v1/systemone"
MAX_QUESTIONS_PER_REQUEST = 8


class JevIntegrationError(Exception):
    """Provider failures without request or response contents."""


class JevQuestionSet:
    def __init__(self, path: Path = DEFAULT_QUESTIONS):
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.version = str(config["version"])
        self.questions = {question["id"]: question for question in config["questions"]}
        if not self.questions:
            raise ValueError("Jev question set must contain at least one question")

    def batches(self) -> list[dict[str, dict[str, Any]]]:
        questions: dict[str, dict[str, Any]] = {}
        for question_id, question in self.questions.items():
            payload = {
                "type": question["type"],
                "instructions": question["question"],
            }
            if question.get("criteria") is not None:
                payload["criteria"] = question["criteria"]
            questions[question_id] = payload
        items = list(questions.items())
        return [dict(items[index : index + MAX_QUESTIONS_PER_REQUEST]) for index in range(0, len(items), MAX_QUESTIONS_PER_REQUEST)]


class JevClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        endpoint: str = JEV_ENDPOINT,
        timeout: float = 20.0,
        retries: int = 2,
        transport: httpx.BaseTransport | None = None,
    ):
        self.api_key = api_key if api_key is not None else os.getenv("JEV_API_KEY")
        self.model = model or os.getenv("JEV_MODEL", "typesafe/jev-1.13")
        self.endpoint = endpoint
        self.timeout = timeout
        self.retries = max(0, retries)
        self._client = httpx.Client(timeout=timeout, transport=transport)

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def evaluate(self, state: dict[str, Any], questions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if not self.configured:
            raise JevIntegrationError("Jev API key is not configured")
        payload = {"model": self.model, "state": state, "questions": questions}
        headers = {
            "Authorization": f"Bearer {self.api_key.strip()}",
            "Content-Type": "application/json",
        }
        for attempt in range(self.retries + 1):
            try:
                response = self._client.post(self.endpoint, json=payload, headers=headers)
                if response.status_code in {429, 529} and attempt < self.retries:
                    time.sleep(min(0.5 * (2**attempt), 4.0))
                    continue
                response.raise_for_status()
                result = response.json()
            except (httpx.HTTPError, ValueError) as error:
                raise JevIntegrationError("Jev request failed") from error
            if not isinstance(result, dict) or not isinstance(result.get("answers"), dict):
                raise JevIntegrationError("Jev returned an invalid response")
            model_id = result.get("model")
            answers = result["answers"]
            if (
                not isinstance(model_id, str)
                or not model_id
                or len(model_id) > 128
                or not set(questions).issubset(answers)
            ):
                raise JevIntegrationError("Jev response did not contain the requested typed answers")
            return {"model": model_id, "answers": answers}
        raise JevIntegrationError("Jev request failed")


def _probability(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1


def validate_answers(
    question_set: JevQuestionSet,
    raw_answers: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    answers: dict[str, dict[str, Any]] = {}
    for question_id, question in question_set.questions.items():
        answer = raw_answers.get(question_id)
        if not isinstance(answer, dict) or answer.get("type") != question["type"]:
            raise JevIntegrationError("Jev returned an invalid typed answer")
        kind = question["type"]
        if kind == "noul":
            value = answer.get("noul")
            if not _probability(value):
                raise JevIntegrationError("Jev returned an invalid Noul probability")
            answers[question_id] = {"type": kind, "noul": float(value)}
        elif kind == "choice":
            choice = answer.get("choice")
            confidence = answer.get("confidence")
            probabilities = answer.get("probabilities")
            if (
                not isinstance(choice, str)
                or choice not in question["criteria"]
                or not _probability(confidence)
                or not _valid_distribution(probabilities, set(question["criteria"]))
            ):
                raise JevIntegrationError("Jev returned an invalid Choice answer")
            answers[question_id] = {
                "type": kind,
                "choice": choice,
                "confidence": float(confidence),
                "probabilities": probabilities,
            }
        elif kind == "score":
            score = answer.get("score")
            confidence = answer.get("confidence")
            probabilities = answer.get("probabilities")
            levels = {str(index) for index in range(len(question["criteria"]))}
            if (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not math.isfinite(score)
                or not 0 <= score < len(question["criteria"])
                or not _probability(confidence)
                or not _valid_distribution(probabilities, levels)
            ):
                raise JevIntegrationError("Jev returned an invalid Score answer")
            answers[question_id] = {
                "type": kind,
                "score": float(score),
                "confidence": float(confidence),
                "probabilities": probabilities,
            }
        else:
            raise JevIntegrationError("Unsupported Jev question type")
    return answers


def _valid_distribution(value: Any, expected_keys: set[str]) -> bool:
    if not isinstance(value, dict) or set(value) != expected_keys:
        return False
    if not all(_probability(probability) for probability in value.values()):
        return False
    return abs(sum(value.values()) - 1.0) <= 0.02
