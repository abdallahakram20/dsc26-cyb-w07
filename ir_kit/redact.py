"""Log redaction. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

import json
import re
from datetime import date

from .secrets import iter_secrets

# Egyptian national ID governorate codes, exactly as in README.md.
GOVERNORATES = {1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                31, 32, 33, 34, 35, 88}

_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_NATIONAL_ID_RE = re.compile(r"(?<![0-9])[23][0-9]{13}(?![0-9])")
_PHONE_RE = re.compile(r"(?<![0-9+])(?:\+20|0020|0)?1[0125][0-9]{8}(?![0-9])")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "api_key", "apikey", "authorization", "cookie",
}


def is_national_id(s: str) -> bool:
    """14 ASCII digits; century digit 2 or 3; a real YYMMDD date in that century; a known governorate."""
    if len(s) != 14 or not all("0" <= ch <= "9" for ch in s):
        return False
    century = 1900 if s[0] == "2" else 2000 if s[0] == "3" else None
    if century is None:
        return False
    try:
        date(century + int(s[1:3]), int(s[3:5]), int(s[5:7]))
    except ValueError:
        return False
    return int(s[7:9]) in GOVERNORATES


def redact_text(text: str) -> str:
    """Escape CR/LF, then redact secrets, bearer tokens, national ids, phone numbers and emails,
    in the exact order given in README.md."""
    out = text.replace("\r", "\\r").replace("\n", "\\n")
    spans = iter_secrets(out)
    if spans:
        parts: list[str] = []
        pos = 0
        for rule_id, start, end in spans:
            parts.append(out[pos:start])
            parts.append(f"[REDACTED:{rule_id}]")
            pos = end
        parts.append(out[pos:])
        out = "".join(parts)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED:bearer]", out)
    out = _NATIONAL_ID_RE.sub(
        lambda m: "[REDACTED:national_id]" if is_national_id(m.group(0)) else m.group(0), out)
    out = _PHONE_RE.sub("[REDACTED:phone]", out)
    out = _EMAIL_RE.sub("[REDACTED:email]", out)
    return out


def _redact_value(value):
    if isinstance(value, dict):
        return {key: _redact_field(key, val) for key, val in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _redact_field(key, value):
    if isinstance(key, str) and key.lower() in _SENSITIVE_KEYS and value is not None and value != "":
        return "[REDACTED:field]"
    return _redact_value(value)


def redact_line(line: str) -> str:
    """If the stripped line is a JSON object, redact it structurally; otherwise redact_text(line)."""
    if line.strip().startswith("{"):
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            return json.dumps(_redact_value(obj), ensure_ascii=False)
    return redact_text(line)
