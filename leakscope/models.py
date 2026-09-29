from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Level = Literal["L4", "L3", "L2", "L1", "L0", "REVIEW"]


class TriageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)
    source: str = Field(default="api", max_length=128)
    found_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    kind: str
    masked: str
    structural_valid: bool | None = None
    is_test_value: bool = False


class TriageResult(BaseModel):
    item_id: str
    source: str
    found_at: datetime | None = None
    level: Level
    reasons: list[str]
    masked_text: str
    evidence: list[Evidence]
    facts: dict[str, Any]
    provenance: dict[str, str]
