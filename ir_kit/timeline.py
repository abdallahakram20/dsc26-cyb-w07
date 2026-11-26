"""Incident timeline builder. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .redact import redact_text

_NGINX_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)')
_WAZUH_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (.+)$")
_CAIRO = ZoneInfo("Africa/Cairo")
_SOURCE_ORDER = {"wazuh": 0, "nginx": 1, "app": 2}


@dataclass(frozen=True)
class Event:
    ts: datetime      # timezone-aware, UTC
    source: str       # "wazuh" | "nginx" | "app"
    message: str      # already redacted


def _parse_nginx(line: str, line_no: int):
    match = _NGINX_RE.match(line)
    if not match:
        return None
    ip, time_str, request, status, _size = match.groups()
    try:
        ts = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return Event(ts=ts.astimezone(timezone.utc), source="nginx",
                 message=redact_text(f'{ip} "{request}" {status}'))


def _parse_app(line: str, line_no: int):
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    try:
        raw_ts = obj["ts"]
        level = obj["level"]
        msg = obj["msg"]
    except KeyError:
        return None
    if not isinstance(raw_ts, str) or not isinstance(level, str) or not isinstance(msg, str):
        return None
    try:
        ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00") if raw_ts.endswith("Z") else raw_ts)
    except ValueError:
        return None
    if ts.tzinfo is None:
        return None
    message = f"{level.upper()} {msg}"
    if "user" in obj and obj["user"] is not None:
        message += f" user={obj['user']}"
    if "doc_id" in obj and obj["doc_id"] is not None:
        message += f" doc_id={obj['doc_id']}"
    return Event(ts=ts.astimezone(timezone.utc), source="app",
                 message=redact_text(message))


def _parse_wazuh(line: str, line_no: int):
    match = _WAZUH_RE.match(line)
    if not match:
        return None
    time_str, message = match.groups()
    try:
        naive = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    ts = naive.replace(tzinfo=_CAIRO, fold=0).astimezone(timezone.utc)
    return Event(ts=ts, source="wazuh", message=redact_text(message))


_PARSERS = {"nginx": _parse_nginx, "app": _parse_app, "wazuh": _parse_wazuh}


def build_timeline(sources: dict[str, str]) -> tuple[list[Event], list[str]]:
    """Parse each source's text, convert to UTC, redact, sort, dedupe. See README.md for the exact
    per-source formats, error reporting and ordering rules. An unknown source name raises ValueError."""
    for name in sources:
        if name not in _PARSERS:
            raise ValueError(f"unknown source: {name}")
    events: list[Event] = []
    errors: list[str] = []
    for source, text in sources.items():
        parser = _PARSERS[source]
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            event = parser(line, line_no)
            if event is None:
                errors.append(f"{source}:{line_no}")
            else:
                events.append((event, line_no))
    events.sort(key=lambda item: (item[0].ts, _SOURCE_ORDER[item[0].source], item[1]))
    seen: set[tuple[datetime, str, str]] = set()
    result: list[Event] = []
    for event, _line_no in events:
        key = (event.ts, event.source, event.message)
        if key in seen:
            continue
        seen.add(key)
        result.append(event)
    return result, errors


def render_markdown(events: list[Event]) -> str:
    """A GitHub-flavoured markdown table: header, separator, one escaped row per event, final newline."""
    lines = ["| Time (UTC) | Source | Event |", "|---|---|---|"]
    for event in events:
        when = event.ts.strftime("%Y-%m-%d %H:%M:%SZ")
        message = event.message.replace("|", "\\|")
        lines.append(f"| {when} | {event.source} | {message} |")
    return "\n".join(lines) + "\n"
