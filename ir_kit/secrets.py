"""Secrets scanner. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARKER = "dsc:allow-secret"

# Provider rule ids and patterns, exactly as in README.md. (Implement with these, do not invent more.)
RULE_IDS = ("private_key", "aws_access_key_id", "github_token", "slack_token", "generic_secret")
PLACEHOLDERS = {"changeme", "password", "example", "redacted", "xxxxxxxx", "secret", "your_token_here"}

_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("generic_secret", re.compile(
        r"""(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api_key|apikey|token))["']?\s*[:=]\s*["']?([^\s"',;]{8,})"""
    )),
]

_MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    path: str
    line: int        # 1-based
    column: int       # 1-based, where the secret starts
    masked: str       # never the full secret


def entropy(s: str) -> float:
    """Shannon entropy of `s`, in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _generic_ok(value: str) -> bool:
    if entropy(value) < 3.0:
        return False
    low = value.lower()
    if low in PLACEHOLDERS:
        return False
    if "example" in low:
        return False
    if low.startswith(("${", "<", "{{", "[redacted")):
        return False
    if value and all(ch in "x*" for ch in value):
        return False
    return True


def iter_secrets(line: str) -> list[tuple[str, int, int]]:
    """Yield (rule_id, start, end), 0-based, end exclusive, for each non-overlapping secret span."""
    candidates: list[tuple[str, int, int]] = []
    for rule_id, pattern in _PATTERNS:
        for match in pattern.finditer(line):
            if rule_id == "generic_secret":
                start, end = match.start(2), match.end(2)
                value = line[start:end]
                if not _generic_ok(value):
                    continue
            else:
                start, end = match.start(), match.end()
                if "EXAMPLE" in line[start:end]:
                    continue
            candidates.append((rule_id, start, end))
    candidates.sort(key=lambda item: (item[1], -(item[2] - item[1])))
    kept: list[tuple[str, int, int]] = []
    last_end = 0
    for rule_id, start, end in candidates:
        if start >= last_end:
            kept.append((rule_id, start, end))
            last_end = end
    return kept


def _masked(secret: str) -> str:
    if len(secret) > 8:
        return secret[:4] + "****"
    return "****"


def scan_text(text: str, path: str) -> list[SecretFinding]:
    """Scan `text` line by line (skipping lines containing ALLOW_MARKER) and return findings."""
    findings: list[SecretFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for rule_id, start, end in iter_secrets(line):
            secret = line[start:end]
            findings.append(SecretFinding(
                rule_id=rule_id,
                path=path,
                line=line_no,
                column=start + 1,
                masked=_masked(secret),
            ))
    return findings


def scan_tree(root) -> list[SecretFinding]:
    """Scan every regular file under `root` (see README.md for what to skip), sorted by path/line/column."""
    root_path = Path(root)
    findings: list[SecretFinding] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames
                       if d != ".git" and not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            file_path = Path(dirpath) / name
            if file_path.is_symlink() or not file_path.is_file():
                continue
            rel = file_path.relative_to(root_path).as_posix()
            if ".git" in file_path.relative_to(root_path).parts:
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size > _MAX_FILE_BYTES:
                continue
            try:
                with open(file_path, "rb") as handle:
                    head = handle.read(1024)
                    if b"\x00" in head:
                        continue
                    handle.seek(0)
                    raw = handle.read()
            except OSError:
                continue
            text = raw.decode("utf-8", errors="replace")
            findings.extend(scan_text(text, rel))
    findings.sort(key=lambda f: (f.path, f.line, f.column))
    return findings
