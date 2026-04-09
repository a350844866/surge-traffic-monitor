#!/usr/bin/env python3
"""
Shared helpers for the Flask dashboard.
"""

import json
import logging
import re
import time
from datetime import date, datetime, timedelta

import requests as http_requests
from flask import Response, g, request, stream_with_context

import config
from db import get_db

log = logging.getLogger("dashboard")


def get_request_db():
    """Get a DB connection scoped to the current request. Auto-closed on teardown."""
    if "db" not in g:
        g.db = get_db()
    return g.db


def close_request_db(exc=None):
    """Teardown handler: close the request-scoped DB connection if opened."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

_rule_map_cache = {}
_rule_map_expires = 0
RULE_MAP_TTL = 300


def _fetch_rule_map():
    """Fetch rules from Surge API and build rule -> policy_group mapping."""
    try:
        resp = http_requests.get(
            f"http://127.0.0.1:{config.SURGE_API_LOCAL_PORT}/v1/rules",
            headers={"X-Key": config.SURGE_API_KEY},
            timeout=5,
        )
        resp.raise_for_status()
        rules = resp.json().get("rules", [])
    except Exception as exc:
        log.warning("Failed to fetch rules from Surge: %s", exc)
        return {}

    mapping = {}
    for line in rules:
        if not line or line.startswith("#"):
            continue
        line = re.sub(r'"[^"]*"', lambda m: m.group().replace(",", "\x00"), line)
        parts = [p.strip().replace("\x00", ",") for p in line.split(",")]
        if len(parts) < 3:
            continue
        rule_type = parts[0].upper()
        rule_value = parts[1]
        policy_group = parts[2].strip('"').strip()
        if not policy_group:
            continue
        key = f"{rule_type} {rule_value}"
        mapping[key] = policy_group
        if rule_type == "RULE-SET" and "/" in rule_value:
            short = rule_value.rstrip("/").rsplit("/", 1)[-1]
            mapping.setdefault(f"RULE-SET {short}", policy_group)
    return mapping


def get_rule_map():
    """Return cached rule -> policy_group mapping, refreshing if stale."""
    global _rule_map_cache, _rule_map_expires
    if time.time() > _rule_map_expires:
        mapping = _fetch_rule_map()
        if mapping:
            _rule_map_cache = mapping
            _rule_map_expires = time.time() + RULE_MAP_TTL
    return _rule_map_cache


def fmt_bytes(n):
    """Format bytes to human readable."""
    if n is None:
        return "0 B"
    n = int(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_date_arg(raw_value, default_day):
    if not raw_value:
        return default_day
    try:
        return date.fromisoformat(raw_value)
    except ValueError:
        return default_day


def _parse_hour_arg(raw_value):
    try:
        hour = int(raw_value)
    except (TypeError, ValueError):
        return 0
    return min(max(hour, 0), 23)


def parse_range():
    """Parse request range and return both display labels and datetime bounds."""
    today = date.today()
    start_day = _parse_date_arg(request.args.get("start"), today)
    end_day = _parse_date_arg(request.args.get("end"), today)
    if end_day < start_day:
        end_day = start_day
    return {
        "start": start_day.isoformat(),
        "end": end_day.isoformat(),
        "start_dt": datetime.combine(start_day, datetime.min.time()),
        "end_dt": datetime.combine(end_day + timedelta(days=1), datetime.min.time()),
    }


def build_time_window(date_str=None, hour_str=None, full_day=False):
    day = _parse_date_arg(date_str, date.today())
    hour = _parse_hour_arg(hour_str)
    start_dt = datetime.combine(day, datetime.min.time())
    end_dt = start_dt + timedelta(days=1)
    if not full_day and hour_str is not None:
        start_dt = start_dt + timedelta(hours=hour)
        end_dt = start_dt + timedelta(hours=1)
    return {
        "date": day.isoformat(),
        "hour": hour,
        "full_day": full_day or hour_str is None,
        "start_dt": start_dt,
        "end_dt": end_dt,
    }


def stream_openrouter(prompt, model=None):
    """Stream an OpenRouter chat completion as SSE text/event-stream."""
    model = (model or "").strip() or config.OPENROUTER_MODEL

    def generate():
        try:
            resp = http_requests.post(
                config.OPENROUTER_BASE_URL,
                headers={
                    "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": True,
                },
                stream=True,
                timeout=120,
            )
            resp.raise_for_status()
            for raw in resp.iter_lines():
                if not raw:
                    continue
                line = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    yield "data: [DONE]\n\n"
                    break
                try:
                    chunk = json.loads(data)
                    delta = chunk["choices"][0]["delta"].get("content", "")
                    if delta:
                        yield f"data: {json.dumps(delta)}\n\n"
                except Exception:
                    continue
        except Exception as exc:
            yield f"data: {json.dumps('[错误] ' + str(exc))}\n\n"
            yield "data: [DONE]\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def ensure_ai_review_jobs_table():
    """Create ai_review_jobs table if it doesn't exist."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ai_review_jobs (
                    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    status          ENUM('running','done','error') NOT NULL DEFAULT 'running',
                    model           VARCHAR(128) DEFAULT '',
                    entry_count     INT UNSIGNED DEFAULT 0,
                    result_md       MEDIUMTEXT,
                    dismissed_count INT UNSIGNED DEFAULT 0,
                    kept_count      INT UNSIGNED DEFAULT 0,
                    error_msg       VARCHAR(1024) DEFAULT NULL,
                    started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at     DATETIME DEFAULT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        db.commit()
    finally:
        db.close()
