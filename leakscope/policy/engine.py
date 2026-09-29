from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY = Path(__file__).resolve().with_name("default.yaml")
if not DEFAULT_POLICY.exists():
    DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"


class PolicyEngine:
    def __init__(self, path: Path = DEFAULT_POLICY):
        self.config = yaml.safe_load(path.read_text(encoding="utf-8"))

    def _matches(self, condition: dict[str, Any], facts: dict[str, Any]) -> bool:
        if "all" in condition:
            return all(self._matches(child, facts) for child in condition["all"])
        if "any" in condition:
            return any(self._matches(child, facts) for child in condition["any"])
        if "abs_difference_gte" in condition:
            left_path, right_path, threshold = condition["abs_difference_gte"]
            left = self._value(facts, left_path)
            right = self._value(facts, right_path)
            return (
                isinstance(left, (int, float))
                and isinstance(right, (int, float))
                and abs(left - right) >= threshold
            )
        name = condition.get("fact")
        value = self._value(facts, name) if isinstance(name, str) else None
        if value is None:
            return False
        if "equals" in condition:
            return value == condition["equals"]
        if "gte" in condition:
            return isinstance(value, (int, float)) and value >= condition["gte"]
        if "gt" in condition:
            return isinstance(value, (int, float)) and value > condition["gt"]
        if "lte" in condition:
            return isinstance(value, (int, float)) and value <= condition["lte"]
        if "lt" in condition:
            return isinstance(value, (int, float)) and value < condition["lt"]
        if "between" in condition:
            low, high = condition["between"]
            return isinstance(value, (int, float)) and low <= value <= high
        return False

    @staticmethod
    def _value(facts: dict[str, Any], path: str) -> Any:
        value: Any = facts
        for key in path.split("."):
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value

    def decide(self, facts: dict[str, Any]) -> tuple[str, list[str]]:
        for rule in self.config["rules"]:
            if self._matches(rule["when"], facts):
                return rule["level"], [rule["reason"]]
        return "REVIEW", ["Deterministic evidence is insufficient; analyst review required"]
