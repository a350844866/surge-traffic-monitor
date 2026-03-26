#!/usr/bin/env python3
"""
Surge Traffic Dashboard - Flask Web App
Port: 8866
"""

import os
import re
import sys
import time
import logging
from datetime import date, timedelta, datetime

import json
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import pymysql
import pymysql.cursors
import requests as http_requests

sys.path.insert(0, os.path.dirname(__file__))
import config

app = Flask(__name__)
log = logging.getLogger("dashboard")

# ─── Rule → Policy Group cache ────────────────────────────────────────────────

_rule_map_cache = {}       # "TYPE VALUE" -> "策略组名"
_rule_map_expires = 0      # unix timestamp
RULE_MAP_TTL = 300         # refresh every 5 minutes


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
    except Exception as e:
        log.warning(f"Failed to fetch rules from Surge: {e}")
        return {}

    mapping = {}
    for line in rules:
        if not line or line.startswith("#"):
            continue
        # Protect commas inside quoted strings
        line = re.sub(r'"[^"]*"', lambda m: m.group().replace(",", "\x00"), line)
        parts = [p.strip().replace("\x00", ",") for p in line.split(",")]
        if len(parts) < 3:
            continue
        rule_type = parts[0].upper()
        rule_value = parts[1]
        policy_group = parts[2].strip('"').strip()
        if not policy_group:
            continue
        # DB stores rule as "TYPE value" (space-separated)
        key = f"{rule_type} {rule_value}"
        mapping[key] = policy_group
        # For RULE-SET with full URL, also add a short-name key (filename without path)
        if rule_type == "RULE-SET" and "/" in rule_value:
            short = rule_value.rstrip("/").rsplit("/", 1)[-1]
            mapping.setdefault(f"RULE-SET {short}", policy_group)
    return mapping


def get_rule_map():
    """Return cached rule -> policy_group mapping, refreshing if stale."""
    global _rule_map_cache, _rule_map_expires
    if time.time() > _rule_map_expires:
        m = _fetch_rule_map()
        if m:
            _rule_map_cache = m
            _rule_map_expires = time.time() + RULE_MAP_TTL
    return _rule_map_cache


def get_db():
    return pymysql.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASS,
        database=config.MYSQL_DB,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
    )


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


app.jinja_env.globals["fmt_bytes"] = fmt_bytes


# ─── API endpoints (return JSON for ECharts) ──────────────────────────────────

def _parse_range():
    """Parse start/end date from request args, default to today."""
    today = date.today().isoformat()
    start = request.args.get("start", today)
    end = request.args.get("end", today)
    # Guard: end must not be before start
    if end < start:
        end = start
    return start, end


@app.route("/api/overview")
def api_overview():
    start, end = _parse_range()
    multi_day = start != end
    db = get_db()
    try:
        with db.cursor() as cur:
            # Summary cards
            cur.execute("""
                SELECT
                    COALESCE(SUM(in_bytes + out_bytes), 0) AS total_bytes,
                    COALESCE(SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL THEN in_bytes + out_bytes ELSE 0 END), 0) AS proxy_bytes,
                    COALESCE(SUM(CASE WHEN policy_name = 'DIRECT' THEN in_bytes + out_bytes ELSE 0 END), 0) AS direct_bytes,
                    COUNT(*) AS total_requests,
                    COUNT(DISTINCT mac_address) AS active_devices
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
            """, (start, end))
            summary = cur.fetchone()

            if multi_day:
                # Daily trend for multi-day range
                cur.execute("""
                    SELECT
                        DATE(start_date) AS label,
                        COALESCE(SUM(in_bytes), 0) AS download,
                        COALESCE(SUM(out_bytes), 0) AS upload
                    FROM requests
                    WHERE DATE(start_date) BETWEEN %s AND %s
                    GROUP BY DATE(start_date)
                    ORDER BY label
                """, (start, end))
            else:
                # Hourly trend for single day
                cur.execute("""
                    SELECT
                        HOUR(start_date) AS label,
                        COALESCE(SUM(in_bytes), 0) AS download,
                        COALESCE(SUM(out_bytes), 0) AS upload
                    FROM requests
                    WHERE DATE(start_date) = %s
                    GROUP BY HOUR(start_date)
                    ORDER BY label
                """, (start,))
            trend_rows = cur.fetchall()

            # Top devices
            cur.execute("""
                SELECT
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    COUNT(*) AS requests
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                GROUP BY r.mac_address
                ORDER BY total_bytes DESC
                LIMIT 10
            """, (start, end))
            top_devices = cur.fetchall()

            # Top domains
            cur.execute("""
                SELECT
                    remote_host AS host,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    COUNT(*) AS requests,
                    MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policy
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
                  AND remote_host IS NOT NULL AND remote_host != ''
                GROUP BY remote_host
                ORDER BY total_bytes DESC
                LIMIT 15
            """, (start, end))
            top_domains = cur.fetchall()

    finally:
        db.close()

    if multi_day:
        trend_labels = [str(r["label"]) for r in trend_rows]
        trend_down   = [int(r["download"]) for r in trend_rows]
        trend_up     = [int(r["upload"]) for r in trend_rows]
    else:
        hourly_map = {r["label"]: r for r in trend_rows}
        trend_labels = [f"{h}:00" for h in range(24)]
        trend_down   = [int(hourly_map.get(h, {}).get("download", 0)) for h in range(24)]
        trend_up     = [int(hourly_map.get(h, {}).get("upload", 0)) for h in range(24)]

    return jsonify({
        "summary": {k: int(v) for k, v in summary.items()},
        "trend": {"labels": trend_labels, "download": trend_down, "upload": trend_up, "multi_day": multi_day},
        "top_devices": [
            {**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])}
            for r in top_devices
        ],
        "top_domains": [
            {**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])}
            for r in top_domains
        ],
    })


@app.route("/api/device/<path:mac>/rename", methods=["POST"])
def api_device_rename(mac):
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()[:255]
    if not name:
        return jsonify({"error": "name required"}), 400

    # Push to Surge first
    try:
        resp = http_requests.post(
            f"http://127.0.0.1:{config.SURGE_API_LOCAL_PORT}/v1/devices",
            headers={"X-Key": config.SURGE_API_KEY, "Content-Type": "application/json"},
            json={"physicalAddress": mac, "name": name},
            timeout=5,
        )
        if not resp.ok:
            return jsonify({"error": f"Surge API error: {resp.text}"}), 502
    except Exception as e:
        return jsonify({"error": f"Surge unreachable: {e}"}), 502

    # Update local DB
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac_address, name) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE name=%s",
                (mac, name, name),
            )
        db.commit()
    finally:
        db.close()

    return jsonify({"ok": True, "name": name})


@app.route("/api/device/<path:mac>")
def api_device(mac):
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            # Device info
            cur.execute("SELECT * FROM devices WHERE mac_address = %s", (mac,))
            device = cur.fetchone()

            # Summary
            cur.execute("""
                SELECT
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL THEN in_bytes + out_bytes ELSE 0 END) AS proxy_bytes,
                    SUM(CASE WHEN policy_name = 'DIRECT' THEN in_bytes + out_bytes ELSE 0 END) AS direct_bytes,
                    COUNT(*) AS requests
                FROM requests
                WHERE mac_address = %s AND DATE(start_date) BETWEEN %s AND %s
            """, (mac, start, end))
            summary = cur.fetchone()

            # Top domains for this device
            cur.execute("""
                SELECT
                    remote_host AS host,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    COUNT(*) AS requests,
                    MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policy
                FROM requests
                WHERE mac_address = %s AND DATE(start_date) BETWEEN %s AND %s
                  AND remote_host IS NOT NULL AND remote_host != ''
                GROUP BY remote_host
                ORDER BY total_bytes DESC
                LIMIT 20
            """, (mac, start, end))
            top_domains = cur.fetchall()

            # Policy breakdown by rule (for policy group mapping)
            cur.execute("""
                SELECT rule, policy_type,
                    SUM(total_bytes) AS total_bytes,
                    SUM(reqs)        AS requests
                FROM (
                    SELECT
                        rule,
                        CASE WHEN policy_name IS NULL OR policy_name = 'DIRECT' THEN 'DIRECT'
                             WHEN policy_name IN ('REJECT', 'REJECT-DROP') THEN 'REJECT'
                             ELSE 'PROXY' END AS policy_type,
                        in_bytes + out_bytes AS total_bytes,
                        1 AS reqs
                    FROM requests
                    WHERE mac_address = %s AND DATE(start_date) BETWEEN %s AND %s
                ) t
                GROUP BY rule, policy_type
            """, (mac, start, end))
            policy_rows = cur.fetchall()

            # Trend over selected range
            cur.execute("""
                SELECT
                    DATE(start_date) AS day,
                    SUM(in_bytes) AS download,
                    SUM(out_bytes) AS upload
                FROM requests
                WHERE mac_address = %s AND DATE(start_date) BETWEEN %s AND %s
                GROUP BY DATE(start_date)
                ORDER BY day
            """, (mac, start, end))
            trend = cur.fetchall()

    finally:
        db.close()

    # Map rule -> policy group, then aggregate
    rule_map = get_rule_map()
    group_agg = {}
    for r in policy_rows:
        pt = r["policy_type"]
        if pt == "DIRECT":
            group = "🎯 直连流量"
        elif pt == "REJECT":
            group = "🛑 拦截/拒绝"
        else:
            group = rule_map.get(r["rule"] or "", r["rule"] or "未知规则")
        if group not in group_agg:
            group_agg[group] = {"policy": group, "total_bytes": 0, "requests": 0}
        group_agg[group]["total_bytes"] += int(r["total_bytes"])
        group_agg[group]["requests"]    += int(r["requests"])
    policies = sorted(group_agg.values(), key=lambda x: x["total_bytes"], reverse=True)

    safe_summary = {k: int(v or 0) for k, v in summary.items()} if summary else {}
    return jsonify({
        "device": device,
        "summary": safe_summary,
        "top_domains": [{**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])} for r in top_domains],
        "policies": policies,
        "trend": [{"day": str(r["day"]), "download": int(r["download"]), "upload": int(r["upload"])} for r in trend],
    })


@app.route("/api/domains")
def api_domains():
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT
                    COALESCE(remote_host, 'unknown') AS host,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    SUM(in_bytes) AS download,
                    SUM(out_bytes) AS upload,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT mac_address) AS devices,
                    MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policies
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
                GROUP BY remote_host
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (start, end))
            domains = cur.fetchall()
    finally:
        db.close()

    return jsonify([
        {**r, "total_bytes": int(r["total_bytes"]),
         "download": int(r["download"]), "upload": int(r["upload"]),
         "requests": int(r["requests"]), "devices": int(r["devices"])}
        for r in domains
    ])


@app.route("/api/policies")
def api_policies():
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            # Policy traffic breakdown
            cur.execute("""
                SELECT
                    COALESCE(policy_name, 'DIRECT') AS policy,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    SUM(in_bytes) AS download,
                    SUM(out_bytes) AS upload,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT mac_address) AS devices
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
                GROUP BY policy_name
                ORDER BY total_bytes DESC
            """, (start, end))
            policies = cur.fetchall()

            # Policy + device breakdown
            cur.execute("""
                SELECT
                    COALESCE(r.policy_name, 'DIRECT') AS policy,
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                  AND r.policy_name != 'DIRECT' AND r.policy_name IS NOT NULL
                GROUP BY r.policy_name, r.mac_address
                ORDER BY total_bytes DESC
                LIMIT 50
            """, (start, end))
            policy_devices = cur.fetchall()

    finally:
        db.close()

    return jsonify({
        "policies": [
            {**r, "total_bytes": int(r["total_bytes"]),
             "download": int(r["download"]), "upload": int(r["upload"]),
             "requests": int(r["requests"]), "devices": int(r["devices"])}
            for r in policies
        ],
        "policy_devices": [
            {**r, "total_bytes": int(r["total_bytes"])}
            for r in policy_devices
        ],
    })


@app.route("/api/domain/<path:host>")
def api_domain(host):
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            # Devices accessing this domain
            cur.execute("""
                SELECT
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    SUM(r.in_bytes) AS download,
                    SUM(r.out_bytes) AS upload,
                    COUNT(*) AS requests,
                    MAX(CASE WHEN r.policy_name = 'DIRECT' OR r.policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policy
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE r.remote_host = %s AND DATE(r.start_date) BETWEEN %s AND %s
                GROUP BY r.mac_address
                ORDER BY total_bytes DESC
            """, (host, start, end))
            devices = cur.fetchall()

            # Summary
            cur.execute("""
                SELECT
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    SUM(in_bytes) AS download,
                    SUM(out_bytes) AS upload,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT mac_address) AS device_count
                FROM requests
                WHERE remote_host = %s AND DATE(start_date) BETWEEN %s AND %s
            """, (host, start, end))
            summary = cur.fetchone()
    finally:
        db.close()

    return jsonify({
        "host": host,
        "summary": {k: int(v or 0) for k, v in summary.items()} if summary else {},
        "devices": [
            {**r, "total_bytes": int(r["total_bytes"]),
             "download": int(r["download"]), "upload": int(r["upload"]),
             "requests": int(r["requests"])}
            for r in devices
        ],
    })


@app.route("/api/policy_groups")
def api_policy_groups():
    start, end = _parse_range()
    rule_map = get_rule_map()

    db = get_db()
    try:
        with db.cursor() as cur:
            # All traffic grouped by rule + policy_type
            cur.execute("""
                SELECT rule, policy_type,
                    SUM(total_bytes) AS total_bytes,
                    SUM(download)    AS download,
                    SUM(upload)      AS upload,
                    SUM(requests)    AS requests,
                    SUM(devices)     AS devices
                FROM (
                    SELECT
                        rule,
                        CASE WHEN policy_name IS NULL OR policy_name = 'DIRECT' THEN 'DIRECT'
                             WHEN policy_name IN ('REJECT', 'REJECT-DROP') THEN 'REJECT'
                             ELSE 'PROXY' END AS policy_type,
                        in_bytes + out_bytes AS total_bytes,
                        in_bytes             AS download,
                        out_bytes            AS upload,
                        1                    AS requests,
                        1                    AS devices
                    FROM requests
                    WHERE DATE(start_date) BETWEEN %s AND %s
                ) t
                GROUP BY rule, policy_type
                ORDER BY total_bytes DESC
            """, (start, end))
            rows = cur.fetchall()
    finally:
        db.close()

    # Map rule -> policy group, then aggregate
    group_agg = {}
    for r in rows:
        pt = r["policy_type"]
        if pt == "DIRECT":
            group = "🎯 直连流量"
        elif pt == "REJECT":
            group = "🛑 拦截/拒绝"
        else:
            rule_str = r["rule"] or "未知规则"
            group = rule_map.get(rule_str, rule_str)
        if group not in group_agg:
            group_agg[group] = {"policy_group": group, "total_bytes": 0,
                                 "download": 0, "upload": 0, "requests": 0, "devices": set()}
        g = group_agg[group]
        g["total_bytes"] += int(r["total_bytes"])
        g["download"] += int(r["download"])
        g["upload"] += int(r["upload"])
        g["requests"] += int(r["requests"])
        g["devices"].add(r["devices"])

    result = sorted(
        [
            {**{k: v for k, v in g.items() if k != "devices"},
             "devices": len(g["devices"])}
            for g in group_agg.values()
        ],
        key=lambda x: x["total_bytes"],
        reverse=True,
    )
    return jsonify(result)


@app.route("/api/policy_group/<path:name>")
def api_policy_group_detail(name):
    start, end = _parse_range()
    rule_map = get_rule_map()

    # Build reverse map: policy_group -> set of rules
    reverse_map = {}
    for rule_key, pg in rule_map.items():
        reverse_map.setdefault(pg, set()).add(rule_key)

    # Determine the SQL filter
    if name == "🎯 直连流量":
        policy_filter = "AND (r.policy_name IS NULL OR r.policy_name = 'DIRECT')"
        filter_params = (start, end)
    elif name == "🛑 拦截/拒绝":
        policy_filter = "AND r.policy_name IN ('REJECT', 'REJECT-DROP')"
        filter_params = (start, end)
    else:
        rules = reverse_map.get(name, set())
        if not rules:
            return jsonify({"policy_group": name, "domains": [], "devices": []})
        placeholders = ",".join(["%s"] * len(rules))
        policy_filter = f"AND r.rule IN ({placeholders}) AND r.policy_name != 'DIRECT' AND r.policy_name IS NOT NULL"
        filter_params = (start, end, *rules)

    db = get_db()
    try:
        with db.cursor() as cur:
            # Top domains using this policy group
            cur.execute(f"""
                SELECT
                    r.remote_host AS host,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    SUM(r.in_bytes) AS download,
                    SUM(r.out_bytes) AS upload,
                    COUNT(*) AS requests
                FROM requests r
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                  {policy_filter}
                  AND r.remote_host IS NOT NULL AND r.remote_host != ''
                GROUP BY r.remote_host
                ORDER BY total_bytes DESC
                LIMIT 50
            """, filter_params)
            domains = cur.fetchall()

            # Devices using this policy group
            cur.execute(f"""
                SELECT
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    COUNT(*) AS requests
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                  {policy_filter}
                GROUP BY r.mac_address
                ORDER BY total_bytes DESC
            """, filter_params)
            devices = cur.fetchall()

            # Summary
            cur.execute(f"""
                SELECT
                    COALESCE(SUM(r.in_bytes + r.out_bytes), 0) AS total_bytes,
                    COALESCE(SUM(r.in_bytes), 0) AS download,
                    COALESCE(SUM(r.out_bytes), 0) AS upload,
                    COUNT(*) AS requests
                FROM requests r
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                  {policy_filter}
            """, filter_params)
            summary = cur.fetchone()
    finally:
        db.close()

    return jsonify({
        "policy_group": name,
        "summary": {k: int(v or 0) for k, v in summary.items()} if summary else {},
        "domains": [
            {**r, "total_bytes": int(r["total_bytes"]),
             "download": int(r["download"]), "upload": int(r["upload"]),
             "requests": int(r["requests"])}
            for r in domains
        ],
        "devices": [
            {**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])}
            for r in devices
        ],
    })


@app.route("/api/devices_list")
def api_devices_list():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT d.mac_address, d.name, d.vendor, d.current_ip,
                       d.dhcp_hostname, d.dns_name
                FROM devices d
                ORDER BY COALESCE(d.name, d.dhcp_hostname, d.mac_address)
            """)
            devices = cur.fetchall()
    finally:
        db.close()
    return jsonify(devices)


@app.route("/api/devices")
def api_devices():
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    d.vendor,
                    d.current_ip,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    SUM(r.in_bytes) AS download,
                    SUM(r.out_bytes) AS upload,
                    COUNT(*) AS requests,
                    SUM(CASE WHEN r.policy_name != 'DIRECT' AND r.policy_name IS NOT NULL
                             THEN r.in_bytes + r.out_bytes ELSE 0 END) AS proxy_bytes,
                    SUM(CASE WHEN r.policy_name = 'DIRECT' OR r.policy_name IS NULL
                             THEN r.in_bytes + r.out_bytes ELSE 0 END) AS direct_bytes
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                GROUP BY r.mac_address
                ORDER BY total_bytes DESC
            """, (start, end))
            devices = cur.fetchall()
    finally:
        db.close()

    return jsonify([
        {**r,
         "total_bytes": int(r["total_bytes"]),
         "download": int(r["download"]), "upload": int(r["upload"]),
         "requests": int(r["requests"]),
         "proxy_bytes": int(r["proxy_bytes"]), "direct_bytes": int(r["direct_bytes"])}
        for r in devices
    ])


# ─── AI Analysis ──────────────────────────────────────────────────────────────

def _stream_openrouter(prompt):
    """Stream an OpenRouter chat completion as SSE text/event-stream."""
    def generate():
        try:
            resp = http_requests.post(
                config.OPENROUTER_BASE_URL,
                headers={
                    "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config.OPENROUTER_MODEL,
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
                if line.startswith("data: "):
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
                        pass
        except Exception as e:
            yield f"data: {json.dumps('[错误] ' + str(e))}\n\n"
            yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/ai/device/<path:mac>")
def ai_device(mac):
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM devices WHERE mac_address = %s", (mac,))
            device = cur.fetchone()
            cur.execute("""
                SELECT
                    remote_host AS host,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    COUNT(*) AS requests,
                    MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL
                             THEN 'DIRECT' ELSE 'PROXY' END) AS policy
                FROM requests
                WHERE mac_address = %s AND DATE(start_date) BETWEEN %s AND %s
                  AND remote_host IS NOT NULL AND remote_host != ''
                GROUP BY remote_host
                ORDER BY total_bytes DESC
                LIMIT 60
            """, (mac, start, end))
            domains = cur.fetchall()
    finally:
        db.close()

    if not domains:
        def empty():
            yield "data: " + json.dumps("该时间段内没有流量数据。") + "\n\n"
            yield "data: [DONE]\n\n"
        return Response(stream_with_context(empty()), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    name = "未知设备"
    if device:
        name = device.get("name") or device.get("dhcp_hostname") or device.get("current_ip") or mac

    domain_lines = "\n".join(
        f"- {d['host']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}  策略:{d['policy']}"
        for d in domains
    )
    prompt = f"""你是一个家庭网络分析助手。以下是设备「{name}」在 {start} 至 {end} 期间访问的域名流量统计（Top 60）：

{domain_lines}

请用中文分析：
1. 这台设备主要在做什么？（推断用途：工作/娱乐/游戏/IoT 等）
2. 流量最大的几个域名属于哪些服务/应用？
3. 有没有值得关注的异常域名或可疑访问？
4. 代理流量和直连流量的比例是否合理？

分析要简洁清晰，使用 Markdown 格式，重点加粗，异常用 ⚠️ 标注。"""

    return _stream_openrouter(prompt)


@app.route("/api/ai/overview")
def ai_overview():
    start, end = _parse_range()
    db = get_db()
    try:
        with db.cursor() as cur:
            # Summary
            cur.execute("""
                SELECT
                    COALESCE(SUM(in_bytes + out_bytes), 0) AS total_bytes,
                    COALESCE(SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL
                                     THEN in_bytes + out_bytes ELSE 0 END), 0) AS proxy_bytes,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT mac_address) AS devices
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
            """, (start, end))
            summary = cur.fetchone()

            # Top domains
            cur.execute("""
                SELECT
                    remote_host AS host,
                    SUM(in_bytes + out_bytes) AS total_bytes,
                    COUNT(*) AS requests,
                    COUNT(DISTINCT mac_address) AS devices,
                    MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL
                             THEN 'DIRECT' ELSE 'PROXY' END) AS policy
                FROM requests
                WHERE DATE(start_date) BETWEEN %s AND %s
                  AND remote_host IS NOT NULL AND remote_host != ''
                GROUP BY remote_host
                ORDER BY total_bytes DESC
                LIMIT 40
            """, (start, end))
            top_domains = cur.fetchall()

            # Top devices
            cur.execute("""
                SELECT
                    COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                    r.mac_address,
                    SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                    COUNT(*) AS requests
                FROM requests r
                LEFT JOIN devices d ON r.mac_address = d.mac_address
                WHERE DATE(r.start_date) BETWEEN %s AND %s
                GROUP BY r.mac_address
                ORDER BY total_bytes DESC
                LIMIT 15
            """, (start, end))
            top_devices = cur.fetchall()
    finally:
        db.close()

    domain_lines = "\n".join(
        f"- {d['host']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}  设备:{d['devices']}台  策略:{d['policy']}"
        for d in top_domains
    )
    device_lines = "\n".join(
        f"- {d['device_name'] or d['mac_address']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}"
        for d in top_devices
    )
    total = int(summary["total_bytes"])
    proxy = int(summary["proxy_bytes"])
    proxy_pct = f"{proxy/total*100:.1f}%" if total else "0%"

    prompt = f"""你是一个家庭网络安全助手。以下是家庭网络在 {start} 至 {end} 期间的流量摘要：

**整体概况**
- 总流量：{fmt_bytes(total)}，代理占比：{proxy_pct}
- 总请求数：{int(summary['requests'])}，活跃设备：{int(summary['devices'])} 台

**流量最高的域名（Top 40）**
{domain_lines}

**流量最高的设备（Top 15）**
{device_lines}

请用中文分析：
1. 整体网络流量是否正常？有没有异常的流量峰值或可疑设备？
2. 有没有可疑的域名访问（恶意软件、广告跟踪、数据外泄特征等）？
3. 哪些设备流量异常偏高，可能需要排查？
4. 代理流量比例是否合理？
5. 给出 2-3 条具体的安全建议。

分析要简洁专业，使用 Markdown 格式，重点加粗，可疑项用 ⚠️ 标注，严重问题用 🚨 标注。"""

    return _stream_openrouter(prompt)


# ─── Suspicious Domains API ───────────────────────────────────────────────────

@app.route("/api/suspicious/count")
def api_suspicious_count():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(severity='high') AS high,
                    SUM(severity='medium') AS medium,
                    SUM(severity='low') AS low
                FROM suspicious_domains
                WHERE dismissed=0
            """)
            row = cur.fetchone()
    finally:
        db.close()
    return jsonify({
        "count": int(row["total"] or 0),
        "high":  int(row["high"] or 0),
        "medium": int(row["medium"] or 0),
        "low":   int(row["low"] or 0),
    })


@app.route("/api/suspicious")
def api_suspicious():
    show_dismissed = request.args.get("show_dismissed") == "1"
    db = get_db()
    try:
        with db.cursor() as cur:
            where = "" if show_dismissed else "WHERE dismissed=0"
            cur.execute(f"""
                SELECT host, detection_type, reason, severity,
                       first_seen, last_seen, request_count, device_count,
                       dismissed, dismissed_at, notes
                FROM suspicious_domains
                {where}
                ORDER BY
                    FIELD(severity,'high','medium','low'),
                    dismissed ASC,
                    last_seen DESC
            """)
            rows = cur.fetchall()
    finally:
        db.close()
    return jsonify([
        {**r,
         "first_seen": r["first_seen"].isoformat() if r["first_seen"] else None,
         "last_seen":  r["last_seen"].isoformat()  if r["last_seen"]  else None,
         "dismissed_at": r["dismissed_at"].isoformat() if r["dismissed_at"] else None,
        }
        for r in rows
    ])


@app.route("/api/suspicious/<path:host>/dismiss", methods=["POST"])
def api_suspicious_dismiss(host):
    data = request.get_json(force=True, silent=True) or {}
    notes = (data.get("notes") or "").strip()[:1024] or None
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE suspicious_domains SET dismissed=1, dismissed_at=NOW(), notes=%s WHERE host=%s",
                (notes, host),
            )
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True})


@app.route("/api/suspicious/<path:host>/restore", methods=["POST"])
def api_suspicious_restore(host):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE suspicious_domains SET dismissed=0, dismissed_at=NULL WHERE host=%s",
                (host,),
            )
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True})


@app.route("/api/suspicious/scan", methods=["POST"])
def api_suspicious_scan():
    from detector import check_domains_blocklist, check_new_domains_heuristic
    db = get_db()
    try:
        h = check_new_domains_heuristic(db)
        n = check_domains_blocklist(db)
    finally:
        db.close()
    return jsonify({"ok": True, "new_flags": h + n})


# ─── Pages ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", today=date.today().isoformat())


@app.route("/device/<path:mac>")
def device_detail(mac):
    return render_template("device.html", mac=mac, today=date.today().isoformat())


@app.route("/domains")
def domains():
    return render_template("domains.html", today=date.today().isoformat())


@app.route("/domain/<path:host>")
def domain_detail(host):
    return render_template("domain.html", host=host, today=date.today().isoformat())


@app.route("/devices")
def devices():
    return render_template("devices.html", today=date.today().isoformat())


@app.route("/policies")
def policies():
    return render_template("policies.html", today=date.today().isoformat())


@app.route("/policy_group/<path:name>")
def policy_group_detail(name):
    return render_template("policy_group.html", name=name, today=date.today().isoformat())


@app.route("/suspicious")
def suspicious():
    return render_template("suspicious.html", today=date.today().isoformat())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8866, debug=False)
