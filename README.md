# dsc26-cyb-w07 · Tanweer incident kit: secrets, redaction, timeline

DSC Summer Internship 2026 · Cybersecurity track · Week 7 (DevSecOps: secrets, logging, incident response)
**Python 3.12 · pytest 9.1.1 · tzdata 2026.4 · standard library only** · expected time 3.5 to 4 hours · everything runs offline

## Scenario

On the night of Thursday 29 October 2026, three days before the data protection compliance date, a
GitHub token for Tanweer's redaction-config repository was found by secret scanning, and shortly
after, a service account downloaded unredacted documents. Hossam needs three small tools before the
next incident: a secrets scanner for Tanweer's repositories, a redactor for every log line the
platform writes, and a timeline builder for the incident report. You build `ir_kit`. All fixtures are
fake; do not paste a real national ID, phone number or token into anything you write here.

## Set up

1. On GitHub create a **public** repository in your own account named exactly `dsc26-cyb-w07`, with no README.
2. Unzip this starter into a folder called `dsc26-cyb-w07`, then:

```bash
git init -b main
uv venv --python 3.12
source .venv/bin/activate            # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt   # pinned versions, including tzdata 2026.4; you cannot add packages
python -m pytest -q                  # the 5 public tests fail until you build the task
git add . && git commit -m "chore: starter from DSC"
git remote add origin https://github.com/<your-username>/dsc26-cyb-w07.git
git push -u origin main
```

Always run tests with `python -m pytest` from the repository root, the way the grader does. Do not
edit anything under `fixtures/`; the grader replaces it with DSC's copy before scoring.

## Files

```
ir_kit/__init__.py
ir_kit/secrets.py     # part 1
ir_kit/redact.py      # part 2
ir_kit/timeline.py    # part 3
fixtures/nginx_access.log
fixtures/app.jsonl
fixtures/wazuh_alerts.log
tests/test_public.py
AI_USAGE.md            # fill in before you submit (the grader checks the headings)
requirements.txt
```

Keep the names and signatures exactly as they are in the starter: the grader imports them. The
dataclasses, `Event` and the governorate set are already written; the functions raise `NotImplementedError`.

## What to build

### 1. `ir_kit/secrets.py`

```python
def entropy(s: str) -> float: ...                  # Shannon entropy in bits per character
def iter_secrets(line: str) -> list[tuple[str, int, int]]: ...   # (rule_id, start, end), 0-based, end exclusive
def scan_text(text: str, path: str) -> list[SecretFinding]: ...
def scan_tree(root) -> list[SecretFinding]: ...
```

Rules, exactly:

| Rule id | Pattern |
|---|---|
| `private_key` | `-----BEGIN (?:RSA \|EC \|OPENSSH \|DSA )?PRIVATE KEY-----` |
| `aws_access_key_id` | `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` |
| `github_token` | `\bgh[pousr]_[A-Za-z0-9]{36}\b` or `\bgithub_pat_[A-Za-z0-9_]{82}\b` |
| `slack_token` | `\bxox[baprs]-[A-Za-z0-9-]{10,}` |
| `generic_secret` | `(?i)([A-Za-z0-9_.-]*(?:password\|passwd\|pwd\|secret\|api_key\|apikey\|token))["']?\s*[:=]\s*["']?([^\s"',;]{8,})`; the secret is group 2 |

(The `\|` above is a literal `|` in the regex.)

- Skip a provider match that contains `EXAMPLE` (the AWS documentation keys).
- Skip a `generic_secret` value whose entropy is below 3.0, or that is a placeholder: lowercased it is
  one of `changeme`, `password`, `example`, `redacted`, `xxxxxxxx`, `secret`, `your_token_here`; or it
  contains `example` in any case; or it starts with `${`, `<`, `{{` or `[redacted` (any case); or it
  consists only of `x` and `*` characters.
- `iter_secrets` returns non-overlapping spans: sort all candidate spans by start, longest first on
  ties, and keep a span only if it starts at or after the end of the last kept one.
- `scan_text` skips any line containing `dsc:allow-secret`. `masked` is the first four characters plus
  `****` if the secret is longer than 8 characters, otherwise `****`.
- `scan_tree(root)` scans every regular file under `root`, skipping symlinks, anything inside a `.git`
  directory, files over 1,000,000 bytes and files with a NUL byte in their first 1,024 bytes. Decode as
  UTF-8 with `errors="replace"`. Paths are relative to `root`, with `/`. Sort by path, line, column.

### 2. `ir_kit/redact.py`

```python
def is_national_id(s: str) -> bool: ...
def redact_text(text: str) -> str: ...
def redact_line(line: str) -> str: ...
```

- `is_national_id(s)`: exactly 14 ASCII digits; first digit 2 (1900s) or 3 (2000s); digits 2-7 a real
  date YYMMDD in that century; digits 8-9 a governorate code in `GOVERNORATES` (`{01, 02, 03, 04,
  11-19, 21-29, 31-35, 88}`). No check-digit test.
- `redact_text(text)`, in this order: replace every CR with the two characters `\r` and every LF with
  `\n`; replace each span from `iter_secrets` with `[REDACTED:<rule_id>]`; replace
  `(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}` with the matched word `bearer` as written, a space and
  `[REDACTED:bearer]`; replace each match of `(?<![0-9])[23][0-9]{13}(?![0-9])` that `is_national_id`
  accepts with `[REDACTED:national_id]`; replace
  `(?<![0-9+])(?:\+20|0020|0)?1[0125][0-9]{8}(?![0-9])` with `[REDACTED:phone]`; replace
  `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` with `[REDACTED:email]`.
- `redact_line(line)`: if the stripped line starts with `{` and parses as a JSON object, redact it
  structurally and return `json.dumps(obj, ensure_ascii=False)`: any key matching (case-insensitive,
  whole key) `password`, `passwd`, `pwd`, `secret`, `token`, `access_token`, `refresh_token`,
  `api_key`, `apikey`, `authorization` or `cookie` with a value that is not `null` or `""` gets the
  value `"[REDACTED:field]"`; other string values go through `redact_text`; lists and nested objects
  are walked; numbers, booleans and `null` are left alone. Otherwise return `redact_text(line)`.
- Redaction is idempotent: redacting an already redacted line changes nothing.

### 3. `ir_kit/timeline.py`

```python
def build_timeline(sources: dict[str, str]) -> tuple[list[Event], list[str]]: ...
def render_markdown(events: list[Event]) -> str: ...
```

- **nginx**: combined log format, matched with `^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)`,
  time parsed with `%d/%b/%Y:%H:%M:%S %z`; message `<ip> "<request>" <status>`.
- **app**: one JSON object per line with `ts` (ISO 8601; `Z` means UTC; a timestamp without an offset
  is an error), `level`, `msg`, and optional `user` and `doc_id`; message `<LEVEL in capitals> <msg>`,
  then ` user=<user>` and ` doc_id=<doc_id>` for those present, in that order, only for fields present.
- **wazuh**: `YYYY-MM-DD HH:MM:SS <message>` in Cairo local time with no offset; attach
  `ZoneInfo("Africa/Cairo")` with `fold=0` (an ambiguous time is the first occurrence) and convert.
- An unknown source name raises `ValueError`. A non-blank line that cannot be parsed is skipped and
  reported as `"<source>:<line number>"` in the errors list, in the order the sources were given, then
  by line.
- Every message goes through `redact_text`. Convert all times to UTC. Sort by time, then source
  (wazuh, nginx, app), then line number. Drop exact duplicates (same time, source and message),
  keeping the first.
- `render_markdown`: a header `| Time (UTC) | Source | Event |`, a separator `|---|---|---|`, then one
  row per event, `| 2026-10-29 20:41:05Z | wazuh | ... |`, with `|` in messages escaped as `\|`, and a
  final newline.

## Starter files DSC provides

- `fixtures/nginx_access.log` (4 lines, one cut off by log rotation, offsets `+0300` and `+0200` on
  the same night), `fixtures/app.jsonl` (5 lines, one without an offset), `fixtures/wazuh_alerts.log`
  (3 lines including a duplicate and a fake `ghp_` token in a secret-scanning alert).

## Public tests

`tests/test_public.py`: an AWS key found and an AWS documentation example key ignored, a generic
password judged by entropy against a placeholder, a national id and phone number redacted (with a 30
February "ID" correctly left alone), a JSON log line kept valid JSON with the password field and an
email redacted, and the three fixture logs merged into one UTC timeline. They are a smoke test, not
the grade.

## How grading works

1. Push, then press **Submit for grading** on DSC Hex. The grader pins your latest commit, clones it,
   replaces your `fixtures/` with DSC's copy, copies in DSC's hidden tests and runs
   `python -m pytest -q -p no:cacheprovider --timeout=30 tests_hidden/` from the repository root with
   Python 3.12, the pinned packages (including tzdata 2026.4, so `zoneinfo` resolves the DST change the
   same way everywhere) and the network off: 30 seconds per test, 4 minutes in total. If the whole run
   passes 4 minutes, no test is credited.
2. Before the run the grader deletes any root `conftest.py`, ignores pytest settings in config files,
   and removes top-level files that would shadow a standard-library or test-tool module. Keep your code
   inside `ir_kit/`.
3. If `AI_USAGE.md` is missing or lacks any of the headings `## Tools`, `## What AI got wrong`,
   `## In my own words`, the grader stops and scores 0 with that reason.
4. You get a score from 0 to 100 and, per hidden test, its public name, pass or fail and a short hint.
   Each ID passes only if every case under it passes. A hidden test that cannot import a name fails on
   its own; the others still run. Property tests use fixed seeds, so the same code always gets the
   same score.
5. 5 grader runs per task per day. Late policy: ×1.0 within 72 hours of the W7 session starting, ×0.6
   for the following 7 days, ×0.5 after that until the programme's final grading date.

### Hidden tests

| ID | Public name | What it checks | Weight |
|---|---|---|---|
| H01 | every rule fires | AKIA and ASIA ids, all five `gh?_` prefixes, a `github_pat_` token, a Slack token, the four private-key headers, `generic_secret` in `.env`, YAML, JSON and Python spellings | 10 |
| H02 | placeholders and examples stay quiet | `EXAMPLE` keys, a 15-character AKIA id, lowercase `akia`, each placeholder form, a low-entropy value, the allow marker | 8 |
| H03 | the scanner never leaks what it finds | Property-generated secrets in random lines: the full value never appears in `repr` of the findings; `masked` is at most 8 characters | 8 |
| H04 | positions are exact | Line and 1-based column for several secrets on one line; overlapping matches reported once | 6 |
| H05 | tree scan skips what it should | `.git/`, a binary file, a 2 MB file and a symlink are skipped; paths relative with `/`; sorted | 8 |
| H06 | national IDs: structure, not just digits | Invalid dates (including 29 February in a non-leap year), unknown governorates, century digits 1 and 4, IDs inside longer numbers, valid IDs for both centuries | 10 |
| H07 | phones and emails | `0`, `+20` and `0020` forms; a Cairo landline `02...` untouched; numbers inside longer digit runs untouched | 6 |
| H08 | bearer tokens and JSON lines | Nested objects and lists, `Password` and `AUTHORIZATION` keys, `null` sensitive values kept, a line starting with `{` that is not JSON | 8 |
| H09 | idempotent, and no log injection | Property test: `redact_line(redact_line(x)) == redact_line(x)` for text and JSON lines; CR and LF never survive | 8 |
| H10 | timeline: three formats to UTC | `Z`, `+00:00` and `+02:00` app times; nginx `+0200` and `+0300`; a malformed line of each kind | 8 |
| H11 | timeline: the night the clocks go back | A Wazuh time just before midnight becomes the first (UTC+3) occurrence; the same local time an hour later becomes the second (UTC+2) occurrence; a July time uses UTC+3 | 8 |
| H12 | timeline: stable order and no duplicates | Ties broken by source order then line; exact duplicates dropped, near-duplicates kept | 6 |
| H13 | timeline: bad input is reported, not fatal | Error list format and order; an unknown source raises `ValueError` | 4 |
| H14 | markdown report | Header, `Z` time format, pipes escaped, messages redacted | 2 |
| | | **Total** | **100** |

**Anti-cheating notes.** H03 and H09 are property tests. H06 and H11 use dates and times not in the
fixtures. The hidden fixtures for H10-H12 are a different, private incident. A redactor that blanks
every digit passes H06's positive cases and fails its negative ones and H07.

## AI tools

AI tools are allowed. `AI_USAGE.md` must keep its three headings (`## Tools`, `## What AI got wrong`,
`## In my own words`). Under `## In my own words`, answer in one or two sentences each, without AI:

1. Your timeline places the Wazuh "download burst" at 20:41:05 UTC. What evidence in the other two logs supports choosing the first 23:41 rather than the second?
2. A token was public on GitHub for ten minutes before you deleted the commit. Why is the incident not over?

The grader does not score the content, but it scores 0 if the file or a heading is missing. Assistants
tend to validate national IDs and phone numbers by digit count alone, and to log local time without an
offset — exactly what this task's hidden tests catch.

## Rules

- Defensive and offline. Standard library only; you cannot add packages. Never paste a real secret,
  national ID, phone number or email into this repository, even redacted; the fixtures are fake on
  purpose.
