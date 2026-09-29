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
        name = condition.get("fact")
        if name not in facts:
            return False
        value = facts[name]
        if "equals" in condition:
            return value == condition["equals"]
        if "gte" in condition:
            return isinstance(value, (int, float)) and value >= condition["gte"]
        return False

    def decide(self, facts: dict[str, Any]) -> tuple[str, list[str]]:
        for rule in self.config["rules"]:
            if self._matches(rule["when"], facts):
                return rule["level"], [rule["reason"]]
        return "REVIEW", ["Deterministic evidence is insufficient; analyst review required"]
