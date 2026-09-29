import base64
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    kind: str
    start: int
    end: int
    value: str
    structural_valid: bool | None = None
    is_test_value: bool = False


_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r"[\s\S]{1,20000}?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_AWS = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GITHUB = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_GENERIC_SECRET = re.compile(
    r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
    r"\b\s*[:=]\s*[\"']?([^\s,;'\"\\}]{4,})",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"\b(?:changeme|change-me|example(?:-key)?|your[-_ ]?(?:api[-_ ]?)?key|"
    r"replace[-_ ]?me|dummy|placeholder|password123|xxxx+)\b|"
    r"\b(?:localhost|example\.(?:com|net|org))\b",
    re.IGNORECASE,
)
_TEST_CARDS = {"4111111111111111", "4012888888881881", "5555555555554444", "378282246310005"}


def _decode_jwt(value: str) -> bool:
    try:
        header, payload, signature = value.split(".")
        if not signature:
            return False
        for segment in (header, payload):
            decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            if not isinstance(json.loads(decoded), dict):
                return False
        return True
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def _luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect(text: str) -> list[Match]:
    matches: list[Match] = []
    for kind, pattern in (("private_key", _PEM), ("aws_access_key", _AWS), ("github_token", _GITHUB)):
        matches.extend(Match(kind, found.start(), found.end(), found.group()) for found in pattern.finditer(text))
    for found in _JWT.finditer(text):
        matches.append(Match("jwt", found.start(), found.end(), found.group(), _decode_jwt(found.group())))
    for found in _CARD.finditer(text):
        digits = "".join(char for char in found.group() if char.isdigit())
        if _luhn(digits):
            matches.append(
                Match("payment_card", found.start(), found.end(), found.group(), True, digits in _TEST_CARDS)
            )
    for found in _GENERIC_SECRET.finditer(text):
        secret = found.group(1)
        if not _PLACEHOLDER.fullmatch(secret):
            start, end = found.span(1)
            matches.append(Match("generic_secret", start, end, secret))
    return sorted(matches, key=lambda match: (match.start, -(match.end - match.start)))


def has_placeholder(text: str) -> bool:
    return _PLACEHOLDER.search(text) is not None


def matching_domains(text: str, domains: set[str]) -> list[str]:
    normalized = {domain.lower().lstrip("@.") for domain in domains}
    return sorted(
        {match.group(1).lower() for match in _EMAIL.finditer(text) if match.group(1).lower() in normalized}
    )
