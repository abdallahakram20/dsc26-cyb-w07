import json
from datetime import datetime, timezone
from pathlib import Path

from ir_kit.redact import redact_line
from ir_kit.secrets import scan_text
from ir_kit.timeline import build_timeline, render_markdown

FIX = Path(__file__).resolve().parent.parent / "fixtures"
FAKE_KEY = "AKIA" + "Q3TW7RZK2M5XNB4H"      # built in two parts so scanners ignore this file


def test_aws_key_found_and_masked_example_key_ignored():
    text = f'AWS_ACCESS_KEY_ID = "{FAKE_KEY}"\naws_docs_key = "AKIAIOSFODNN7EXAMPLE"\n'
    found = scan_text(text, "deploy/settings.py")
    assert [(f.rule_id, f.line) for f in found] == [("aws_access_key_id", 1)]
    assert FAKE_KEY not in repr(found)


def test_generic_password_uses_entropy_and_placeholders():
    found = scan_text('DB_PASSWORD="Tanweer#2026!prod"\nSMTP_PASSWORD="changeme"\n', "app/.env")
    assert [(f.rule_id, f.line) for f in found] == [("generic_secret", 1)]


def test_national_id_and_phone_are_redacted():
    line = "clerk viewed record for 29803150101235 (mobile +201001234567), ref 29802301234567"
    out = redact_line(line)
    assert "29803150101235" not in out and "[REDACTED:national_id]" in out
    assert "[REDACTED:phone]" in out
    assert "29802301234567" in out          # 30 February is not a birth date, so not an ID


def test_json_log_stays_json():
    line = json.dumps({"ts": "2026-10-29T20:40:10Z", "user": "svc-export", "password": "hunter2-hunter2",
                       "msg": "login from mona@tanweer.example"})
    obj = json.loads(redact_line(line))
    assert obj["password"] == "[REDACTED:field]" and obj["user"] == "svc-export"
    assert obj["msg"] == "login from [REDACTED:email]"


def test_timeline_merges_sources_in_utc():
    events, errors = build_timeline({
        "nginx": (FIX / "nginx_access.log").read_text(),
        "app": (FIX / "app.jsonl").read_text(),
        "wazuh": (FIX / "wazuh_alerts.log").read_text(),
    })
    assert errors == ["nginx:3", "app:4"]
    times = [e.ts for e in events]
    assert times == sorted(times) and all(t.tzinfo == timezone.utc for t in times)
    assert events[0].ts == datetime(2026, 10, 29, 19, 58, 40, tzinfo=timezone.utc)   # wazuh, Cairo +03
    md = render_markdown(events)
    assert "ghp_" not in md and md.startswith("| Time (UTC) | Source | Event |")
