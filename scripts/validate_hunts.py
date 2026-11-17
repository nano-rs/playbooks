#!/usr/bin/env python3
"""Validate the hunt playbooks in hunts/ against the nano playbook v2 contract.

Mirrors the import rules of the nano product (nanosiem-core hunts::spec and
hunts::playbook) so a file that would fail to sync, or a pivot that would
never run, fails the pull request instead:

  * the YAML frontmatter parses and declares `kind: hunt`;
  * the body has an opening /query or /baseline step and no /decision,
    /review or /action step;
  * schedule, lookback_window, mitre ids and the budget are inside the
    product's ceilings;
  * `hypothesis` is present and bounded;
  * `pivots`: 1 to 12, unique names, known roles / datasets / scorers, the
    scorer thresholds in range, and every `dataset: signals` query obeys the
    guarded-SQL shape (one SELECT, {signals} read, window bound, no SETTINGS,
    no comments, only {signals} / {events} / subqueries, no comma joins);
  * events pivots use OCSF field names, never the legacy UDM ones;
  * risk_weight 1..10 and default_severity a known value; no `enabled` or
    `escalation_mode` (both are decisions made in the product).

Optionally, with NANO_VALIDATE_URL and NANO_VALIDATE_TOKEN set, every pivot is
also compiled by a live nano (POST /api/hunts/pivots/validate, which runs
nothing), the same check hunt create and PATCH apply.

Usage: python3 scripts/validate_hunts.py [hunts-dir]
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

MAX_PIVOTS = 12
MAX_PIVOT_QUERY_CHARS = 8192
MAX_HYPOTHESIS_CHARS = 4000
PIVOT_NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
SCORER_FIELD_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CEILINGS = {
    "max_turns": 200,
    "max_tool_calls": 1000,
    "max_rows": 100_000,
    "max_wall_seconds": 3600,
}
MAX_LOOKBACK_MINUTES = 30 * 24 * 60
CATEGORIES = {"identity", "endpoint", "cloud", "data", "network", "email"}
WINDOW_START = "{earliest:DateTime64(6, 'UTC')}"
WINDOW_END = "{latest:DateTime64(6, 'UTC')}"
STEP_RE = re.compile(r"^/(query|pivot|enrichment|baseline|lead|decision|action|review|note):", re.M)
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^[a-z-]{1,64}$")
# Legacy UDM column names that must not appear as field names in an OCSF
# pivot. Matched as whole field tokens (not inside a dotted OCSF path).
UDM_FIELDS = {
    "src_ip", "dest_ip", "src_host", "dest_host", "src_port", "dest_port", "user",
    "process_name", "command_line", "parent_process_name", "parent_command_line",
    "process_hash", "file_hash", "file_action", "auth_type", "auth_result",
    "event_id", "bytes_in", "bytes_out", "dvc_ip", "src_user",
    "dest_user", "user_agent", "http_method", "query_type",
    "enriched_src_country", "enriched_src_asn",
}
FIELD_TOKEN_RE = re.compile(r"(?<![\w.`\"'])([a-z_][a-z0-9_]*)(?=\s*(=|!=|<|>|\bIN\b|\bby\b|,|\)|\||$))", re.I)


def fail(errors: list[str], file: str, message: str) -> None:
    errors.append(f"{file}: {message}")


def split_frontmatter(text: str):
    text = text.lstrip("﻿")
    if not text.startswith("---"):
        return None, text
    lines = text.split("\n")
    for i in range(1, len(lines)):
        if lines[i].rstrip("\r") in ("---", "..."):
            return "\n".join(lines[1:i]), "\n".join(lines[i + 1 :])
    return None, text


def lookback_minutes(raw: str):
    m = re.fullmatch(r"(\d+)([mhd])", raw.strip().lower())
    if not m or int(m.group(1)) <= 0:
        return None
    return int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]


def table_targets(query: str) -> list[str]:
    tokens = query.split()
    out = []
    for i, tok in enumerate(tokens):
        kw = tok.lstrip("(").lower()
        if kw in ("from", "join") and i + 1 < len(tokens):
            out.append(tokens[i + 1].rstrip(",)"))
    return out


def has_comma_join(query: str) -> bool:
    tokens = query.split()
    for i, tok in enumerate(tokens):
        if tok.lstrip("(").lower() == "from":
            for t in tokens[i + 1 : i + 4]:
                if t.endswith(",") or t == ",":
                    return True
                low = t.lower()
                if low in ("where", "join") or low.endswith(")"):
                    break
    return False


def check_signals_query(name: str, q: str) -> list[str]:
    problems = []
    head = q.lstrip().lower()
    if not (head.startswith("select") or head.startswith("with")):
        problems.append(f"signals pivot `{name}` must be one SELECT (or WITH ... SELECT)")
    if ";" in q:
        problems.append(f"signals pivot `{name}` must be a single statement")
    if "{signals}" not in q:
        problems.append(f"signals pivot `{name}` must read FROM {{signals}}")
    if WINDOW_START not in q or WINDOW_END not in q:
        problems.append(f"signals pivot `{name}` must bind the sweep window ({WINDOW_START} / {WINDOW_END})")
    if has_comma_join(q):
        problems.append(f"signals pivot `{name}` may not use a comma join; use JOIN")
    for target in table_targets(q):
        if not (target.startswith("(") or target in ("{signals}", "{events}")):
            problems.append(f"signals pivot `{name}` may read only {{signals}}, {{events}} or a subquery (found `{target[:80]}`)")
    if re.search(r"\bsettings\b", q, re.I):
        problems.append(f"signals pivot `{name}` may not carry SETTINGS")
    if "--" in q or "/*" in q:
        problems.append(f"signals pivot `{name}` may not contain comments")
    if re.search(r"\bprewhere\b", q, re.I):
        problems.append(f"signals pivot `{name}` must not use PREWHERE (one WHERE; auto move-to-prewhere places it)")
    # Each read of a table placeholder must be window-bound.
    reads = q.count("{events}") + q.count("{signals}")
    bounds = q.count(WINDOW_START)
    if bounds < reads:
        problems.append(f"signals pivot `{name}` reads {reads} table(s) but binds the window {bounds} time(s); bound every read")
    return problems


def strip_quoted(q: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', q)


def check_events_query(name: str, q: str) -> list[str]:
    problems = []
    search = strip_quoted(q)
    # Names the query defines itself (`... AS bytes_out`, `eval x=...`) are
    # result columns, not field references.
    aliases = {a.lower() for a in re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", search, re.I)}
    aliases |= {a.lower() for a in re.findall(r"\|\s*eval\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", search, re.I)}
    for m in FIELD_TOKEN_RE.finditer(search):
        token = m.group(1)
        if token.lower() in UDM_FIELDS and token.lower() not in aliases:
            problems.append(f"pivot `{name}` uses `{token}`, a legacy UDM name and not an ocsf_logs column; hunts are OCSF only")
    banned = re.search(r"\|\s*(ai|inputlookup|join|append|transaction|sequence|output)\b", q)
    if banned:
        problems.append(f"pivot `{name}` uses `{banned.group(1)}`, which a deterministic pivot may not")
    return problems


def warn_events_query(name: str, q: str) -> list[str]:
    warnings = []
    search = strip_quoted(q).split("|", 1)[0]
    if not re.search(r"\bclass_uid\s*(=|IN\b)", search, re.I):
        warnings.append(f"pivot `{name}` does not filter on class_uid; make sure it is cheap over the whole window")
    return warnings


def check_file(path: Path, errors: list[str]) -> list[dict]:
    file = path.name
    text = path.read_text(encoding="utf-8")
    raw_fm, body = split_frontmatter(text)
    if raw_fm is None:
        fail(errors, file, "no YAML frontmatter")
        return []
    try:
        fm = yaml.safe_load(raw_fm) or {}
    except yaml.YAMLError as e:
        fail(errors, file, f"frontmatter does not parse: {e}")
        return []
    if fm.get("kind") != "hunt":
        fail(errors, file, "frontmatter must declare kind: hunt")
        return []
    for key in ("title", "subtitle", "category"):
        if not fm.get(key):
            fail(errors, file, f"missing `{key}`")
    if fm.get("category") and str(fm["category"]).strip() not in CATEGORIES:
        fail(errors, file, f"category `{fm['category']}` is not one of {sorted(CATEGORIES)}")
    if "enabled" in fm:
        fail(errors, file, "`enabled` has no effect: a synced hunt always lands disabled; remove it")

    steps = STEP_RE.findall(body)
    if not any(s in ("query", "baseline") for s in steps):
        fail(errors, file, "the body needs an opening /query or /baseline step")
    for s in steps:
        if s in ("decision", "review", "action"):
            fail(errors, file, f"/{s} is not available to hunts")

    if fm.get("lookback_window") is not None:
        minutes = lookback_minutes(str(fm["lookback_window"]))
        if minutes is None:
            fail(errors, file, f"lookback_window `{fm['lookback_window']}` must look like 15m, 24h or 7d")
        elif minutes > MAX_LOOKBACK_MINUTES:
            fail(errors, file, "lookback_window exceeds the 30d ceiling")
    if fm.get("mitre_technique") and not TECHNIQUE_RE.match(str(fm["mitre_technique"]).upper()):
        fail(errors, file, f"mitre_technique `{fm['mitre_technique']}` is not an ATT&CK id")
    if fm.get("mitre_tactic") and not TACTIC_RE.match(str(fm["mitre_tactic"]).lower()):
        fail(errors, file, f"mitre_tactic `{fm['mitre_tactic']}` is not a tactic shortname")

    budget = fm.get("budget") or {}
    for key, value in budget.items():
        if key not in CEILINGS:
            fail(errors, file, f"budget.{key} is not a budget field")
            continue
        if not isinstance(value, int) or value <= 0:
            fail(errors, file, f"budget.{key} must be a positive integer")
        elif value > CEILINGS[key]:
            fail(errors, file, f"budget.{key} {value} exceeds the ceiling {CEILINGS[key]}")

    hyp = fm.get("hypothesis")
    if not isinstance(hyp, str) or not hyp.strip():
        fail(errors, file, "missing `hypothesis`")
    elif len(hyp.strip()) > MAX_HYPOTHESIS_CHARS:
        fail(errors, file, f"hypothesis exceeds {MAX_HYPOTHESIS_CHARS} characters")

    rw = fm.get("risk_weight")
    if rw is not None and (not isinstance(rw, int) or not 1 <= rw <= 10):
        fail(errors, file, "risk_weight must be an integer 1..10")
    sev = fm.get("default_severity")
    if sev is not None and str(sev).strip().lower() not in SEVERITIES - {"critical"}:
        fail(errors, file, "default_severity must be high, medium, low or info (critical is set in the product)")
    if "escalation_mode" in fm:
        fail(errors, file, "`escalation_mode` is chosen in the product, never by a file; remove it")

    pivots = fm.get("pivots")
    if not isinstance(pivots, list) or not pivots:
        fail(errors, file, "missing `pivots` (1 to 12)")
        return []
    if len(pivots) > MAX_PIVOTS:
        fail(errors, file, f"at most {MAX_PIVOTS} pivots")
    seen = set()
    roles = set()
    out = []
    for i, p in enumerate(pivots, 1):
        if not isinstance(p, dict):
            fail(errors, file, f"pivot #{i} is not a mapping")
            continue
        unknown = set(p) - {"name", "role", "query", "scorer", "dataset", "sources"}
        if unknown:
            fail(errors, file, f"pivot #{i} has unknown keys {sorted(unknown)}")
        name = str(p.get("name", "")).strip().lower()
        if not PIVOT_NAME_RE.match(name):
            fail(errors, file, f"pivot #{i} name `{p.get('name')}` must be 1-64 of a-z, 0-9, _ or -")
        if name in seen:
            fail(errors, file, f"pivot name `{name}` is used twice")
        seen.add(name)
        role = p.get("role")
        if role not in ("coverage", "discovery"):
            fail(errors, file, f"pivot `{name}` role must be coverage or discovery")
        roles.add(role)
        dataset = p.get("dataset", "events")
        if dataset not in ("events", "signals"):
            fail(errors, file, f"pivot `{name}` dataset must be events or signals")
        q = str(p.get("query", "")).strip()
        if not q:
            fail(errors, file, f"pivot `{name}` has an empty query")
        if len(q) > MAX_PIVOT_QUERY_CHARS:
            fail(errors, file, f"pivot `{name}` query exceeds {MAX_PIVOT_QUERY_CHARS} characters")
        problems = check_signals_query(name, q) if dataset == "signals" else check_events_query(name, q)
        for problem in problems:
            fail(errors, file, problem)
        if dataset == "events":
            for w in warn_events_query(name, q):
                print(f"WARN  {file}: {w}")
        scorer = p.get("scorer")
        if scorer is not None:
            if not isinstance(scorer, dict) or set(scorer) - {"method", "field", "threshold"}:
                fail(errors, file, f"pivot `{name}` scorer must be {{method, field, threshold}}")
            else:
                method = scorer.get("method")
                t = scorer.get("threshold")
                if method not in ("zscore", "iqr", "rare"):
                    fail(errors, file, f"pivot `{name}` scorer method must be zscore, iqr or rare")
                if not SCORER_FIELD_RE.match(str(scorer.get("field", ""))):
                    fail(errors, file, f"pivot `{name}` scorer field is invalid")
                if not isinstance(t, (int, float)) or (
                    method in ("zscore", "iqr") and not 0 < t <= 100
                ) or (method == "rare" and not 1 <= t <= 1_000_000):
                    fail(errors, file, f"pivot `{name}` scorer threshold {t} is out of range")
        out.append({"name": name, "dataset": dataset, "query": q, "sources": p.get("sources", [])})
    if "discovery" not in roles:
        fail(errors, file, "at least one pivot must have role: discovery")
    return out


def live_compile(file: str, pivots: list[dict], errors: list[str]) -> None:
    url = os.environ.get("NANO_VALIDATE_URL")
    token = os.environ.get("NANO_VALIDATE_TOKEN")
    if not url or not token:
        return
    for p in pivots:
        body = json.dumps({"query": p["query"], "dataset": p["dataset"], "sources": p["sources"]}).encode()
        req = urllib.request.Request(
            url.rstrip("/") + "/api/hunts/pivots/validate",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                verdict = json.load(resp)
        except (urllib.error.URLError, ValueError) as e:
            fail(errors, file, f"pivot `{p['name']}` could not be validated on {url}: {e}")
            continue
        if not verdict.get("ok"):
            msgs = "; ".join(e.get("message", "") for e in verdict.get("errors", []))
            fail(errors, file, f"pivot `{p['name']}` does not compile: {msgs}")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "hunts")
    files = sorted(f for f in root.glob("*.md") if f.name != "README.md")
    errors: list[str] = []
    total = 0
    for f in files:
        pivots = check_file(f, errors)
        total += len(pivots)
        live_compile(f.name, pivots, errors)
    for e in errors:
        print(f"ERROR {e}")
    print(f"{len(files)} hunts, {total} pivots, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
