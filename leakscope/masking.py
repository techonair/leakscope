import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

from leakscope.detectors import Match, detect

MAX_ITEM_CHARS = 12_000
MAX_RAW_CHARS = 1_000_000
MAX_SCAN_CHARS = MAX_ITEM_CHARS + 20_000
_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}


@dataclass(frozen=True)
class Sanitized:
    text: str
    matches: list[Match]
    fingerprints: list[str]
    truncated: bool


def normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(
        char
        for char in normalized
        if char not in _ZERO_WIDTH and (char in "\n\r\t" or unicodedata.category(char) != "Cc")
    )[:MAX_RAW_CHARS]


def _fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def sanitize(text: str, key: bytes) -> Sanitized:
    normalized = normalize(text)
    truncated = len(normalized) > MAX_ITEM_CHARS
    matches = detect(normalized[:MAX_SCAN_CHARS])
    selected: list[Match] = []
    cursor = -1
    for match in matches:
        if match.start >= cursor:
            selected.append(match)
            cursor = match.end

    masked = normalized
    for match in reversed(selected):
        masked = masked[: match.start] + f"[REDACTED:{match.kind}]" + masked[match.end :]
    secret_fingerprints = [_fingerprint(match.value, key) for match in selected]
    return Sanitized(
        text=("[TRUNCATED: preview omitted]" if truncated else masked),
        matches=selected,
        fingerprints=secret_fingerprints,
        truncated=truncated,
    )


def item_fingerprint(text: str, key: bytes) -> str:
    return _fingerprint(normalize(text), key)
