import argparse
import json
import sys
from pathlib import Path
from typing import Any

from leakscope.models import TriageRequest
from leakscope.service import TriageService


def _records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [record if isinstance(record, dict) else {"text": str(record)} for record in value]
    if isinstance(value, dict) and "text" not in value:
        return [{"text": json.dumps(value, ensure_ascii=True)}]
    return [value] if isinstance(value, dict) else [{"text": str(value)}]


def main() -> None:
    parser = argparse.ArgumentParser(prog="leakscope")
    subparsers = parser.add_subparsers(dest="command", required=True)
    triage_parser = subparsers.add_parser("triage", help="Triage a JSON, JSONL, or plain-text file")
    triage_parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        content = args.input.read_text(encoding="utf-8")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = [{"text": line} for line in content.splitlines() if line.strip()]
        results = []
        service = TriageService()
        for record in _records(parsed):
            text = str(record.get("text", record.get("raw", "")))
            request = TriageRequest(
                text=text,
                source=str(record.get("source", record.get("source_type", "file"))),
                found_at=record.get("found_at"),
                metadata=record.get("metadata", {}) if isinstance(record.get("metadata", {}), dict) else {},
            )
            results.append(service.triage(request).model_dump())
        json.dump(results, sys.stdout, ensure_ascii=True, indent=2)
        sys.stdout.write("\n")
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
