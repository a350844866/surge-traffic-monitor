from flask import Blueprint, jsonify, request

import config
from web_common import build_time_window, get_request_db, get_rule_map, parse_range
import requests as http_requests

bp = Blueprint("traffic", __name__)


@bp.route("/api/overview")
def api_overview():
    range_info = parse_range()
    start = range_info["start"]
    end = range_info["end"]
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    multi_day = start != end
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT
                COALESCE(SUM(in_bytes + out_bytes), 0) AS total_bytes,
                COALESCE(SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL THEN in_bytes + out_bytes ELSE 0 END), 0) AS proxy_bytes,
                COALESCE(SUM(CASE WHEN policy_name = 'DIRECT' THEN in_bytes + out_bytes ELSE 0 END), 0) AS direct_bytes,
                COUNT(*) AS total_requests,
                COUNT(DISTINCT mac_address) AS active_devices
            FROM requests
            WHERE start_date >= %s AND start_date < %s
        """, (start_dt, end_dt))
        summary = cur.fetchone()

        if multi_day:
            cur.execute("""
                SELECT
                    DATE(start_date) AS label,
                    COALESCE(SUM(in_bytes), 0) AS download,
                    COALESCE(SUM(out_bytes), 0) AS upload
                FROM requests
                WHERE start_date >= %s AND start_date < %s
                GROUP BY DATE(start_date)
                ORDER BY label
            """, (start_dt, end_dt))
        else:
            cur.execute("""
                SELECT
                    HOUR(start_date) AS label,
                    COALESCE(SUM(in_bytes), 0) AS download,
                    COALESCE(SUM(out_bytes), 0) AS upload
                FROM requests
                WHERE start_date >= %s AND start_date < %s
                GROUP BY HOUR(start_date)
                ORDER BY label
            """, (start_dt, end_dt))
        trend_rows = cur.fetchall()

        cur.execute("""
            SELECT
                COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                r.mac_address,
                SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                COUNT(*) AS requests
            FROM requests r
            LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY total_bytes DESC
            LIMIT 10
        """, (start_dt, end_dt))
        top_devices = cur.fetchall()

        cur.execute("""
            SELECT
                remote_host AS host,
                SUM(in_bytes + out_bytes) AS total_bytes,
                COUNT(*) AS requests,
                MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY total_bytes DESC
            LIMIT 15
        """, (start_dt, end_dt))
        top_domains = cur.fetchall()

    if multi_day:
        trend_labels = [str(r["label"]) for r in trend_rows]
        trend_down = [int(r["download"]) for r in trend_rows]
        trend_up = [int(r["upload"]) for r in trend_rows]
    else:
        hourly_map = {r["label"]: r for r in trend_rows}
        trend_labels = [f"{h}:00" for h in range(24)]
        trend_down = [int(hourly_map.get(h, {}).get("download", 0)) for h in range(24)]
        trend_up = [int(hourly_map.get(h, {}).get("upload", 0)) for h in range(24)]

    return jsonify({
        "summary": {k: int(v) for k, v in summary.items()},
        "trend": {"labels": trend_labels, "download": trend_down, "upload": trend_up, "multi_day": multi_day},
        "top_devices": [{**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])} for r in top_devices],
        "top_domains": [{**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])} for r in top_domains],
    })


@bp.route("/api/overview/hour")
def api_overview_hour():
    time_window = build_time_window(
        request.args.get("date"),
        request.args.get("hour"),
        request.args.get("full_day") == "1",
    )
    date_str = time_window["date"]
    hour = time_window["hour"]
    full_day = time_window["full_day"]
    start_dt = time_window["start_dt"]
    end_dt = time_window["end_dt"]

    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT
                remote_host AS host,
                COALESCE(SUM(out_bytes), 0) AS upload_bytes,
                COALESCE(SUM(in_bytes), 0) AS download_bytes,
                COUNT(*) AS requests,
                MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL
                         THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY upload_bytes DESC
            LIMIT 20
        """, (start_dt, end_dt))
        top_domains = cur.fetchall()

        cur.execute("""
            SELECT
                COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                r.mac_address,
                COALESCE(SUM(r.out_bytes), 0) AS upload_bytes,
                COALESCE(SUM(r.in_bytes), 0) AS download_bytes,
                COUNT(*) AS requests
            FROM requests r
            LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY upload_bytes DESC
            LIMIT 10
        """, (start_dt, end_dt))
        top_devices = cur.fetchall()

    return jsonify({
        "date": date_str,
        "hour": hour,
        "full_day": full_day,
        "top_domains": [
            {**r, "upload_bytes": int(r["upload_bytes"]), "download_bytes": int(r["download_bytes"]), "requests": int(r["requests"])}
            for r in top_domains
        ],
        "top_devices": [
            {**r, "upload_bytes": int(r["upload_bytes"]), "download_bytes": int(r["download_bytes"]), "requests": int(r["requests"])}
            for r in top_devices
        ],
    })


@bp.route("/api/device/<path:mac>/rename", methods=["POST"])
def api_device_rename(mac):
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()[:255]
    if not name:
        return jsonify({"error": "name required"}), 400

    try:
        resp = http_requests.post(
            f"http://127.0.0.1:{config.SURGE_API_LOCAL_PORT}/v1/devices",
            headers={"X-Key": config.SURGE_API_KEY, "Content-Type": "application/json"},
            json={"physicalAddress": mac, "name": name},
            timeout=5,
        )
        if not resp.ok:
            return jsonify({"error": f"Surge API error: {resp.text}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Surge unreachable: {exc}"}), 502

    db = get_request_db()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO devices (mac_address, name) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE name=%s",
            (mac, name, name),
        )
    db.commit()

    return jsonify({"ok": True, "name": name})


@bp.route("/api/device/<path:mac>")
def api_device(mac):
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE mac_address = %s", (mac,))
        device = cur.fetchone()

        cur.execute("""
            SELECT
                SUM(in_bytes + out_bytes) AS total_bytes,
                SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL THEN in_bytes + out_bytes ELSE 0 END) AS proxy_bytes,
                SUM(CASE WHEN policy_name = 'DIRECT' THEN in_bytes + out_bytes ELSE 0 END) AS direct_bytes,
                COUNT(*) AS requests
            FROM requests
            WHERE mac_address = %s AND start_date >= %s AND start_date < %s
        """, (mac, start_dt, end_dt))
        summary = cur.fetchone()

        cur.execute("""
            SELECT
                remote_host AS host,
                SUM(in_bytes + out_bytes) AS total_bytes,
                COUNT(*) AS requests,
                MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE mac_address = %s AND start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY total_bytes DESC
            LIMIT 20
        """, (mac, start_dt, end_dt))
        top_domains = cur.fetchall()

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
                WHERE mac_address = %s AND start_date >= %s AND start_date < %s
            ) t
            GROUP BY rule, policy_type
        """, (mac, start_dt, end_dt))
        policy_rows = cur.fetchall()

        cur.execute("""
            SELECT
                DATE(start_date) AS day,
                SUM(in_bytes) AS download,
                SUM(out_bytes) AS upload
            FROM requests
            WHERE mac_address = %s AND start_date >= %s AND start_date < %s
            GROUP BY DATE(start_date)
            ORDER BY day
        """, (mac, start_dt, end_dt))
        trend = cur.fetchall()

    rule_map = get_rule_map()
    group_agg = {}
    for row in policy_rows:
        policy_type = row["policy_type"]
        if policy_type == "DIRECT":
            group = "🎯 直连流量"
        elif policy_type == "REJECT":
            group = "🛑 拦截/拒绝"
        else:
            group = rule_map.get(row["rule"] or "", row["rule"] or "未知规则")
        if group not in group_agg:
            group_agg[group] = {"policy": group, "total_bytes": 0, "requests": 0}
        group_agg[group]["total_bytes"] += int(row["total_bytes"])
        group_agg[group]["requests"] += int(row["requests"])
    policies = sorted(group_agg.values(), key=lambda item: item["total_bytes"], reverse=True)

    safe_summary = {k: int(v or 0) for k, v in summary.items()} if summary else {}
    return jsonify({
        "device": device,
        "summary": safe_summary,
        "top_domains": [{**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])} for r in top_domains],
        "policies": policies,
        "trend": [{"day": str(r["day"]), "download": int(r["download"]), "upload": int(r["upload"])} for r in trend],
    })


@bp.route("/api/domains")
def api_domains():
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
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
            WHERE start_date >= %s AND start_date < %s
            GROUP BY remote_host
            ORDER BY total_bytes DESC
            LIMIT 100
        """, (start_dt, end_dt))
        domains = cur.fetchall()

    return jsonify([
        {**r, "total_bytes": int(r["total_bytes"]), "download": int(r["download"]), "upload": int(r["upload"]), "requests": int(r["requests"]), "devices": int(r["devices"])}
        for r in domains
    ])


@bp.route("/api/policies")
def api_policies():
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT
                COALESCE(policy_name, 'DIRECT') AS policy,
                SUM(in_bytes + out_bytes) AS total_bytes,
                SUM(in_bytes) AS download,
                SUM(out_bytes) AS upload,
                COUNT(*) AS requests,
                COUNT(DISTINCT mac_address) AS devices
            FROM requests
            WHERE start_date >= %s AND start_date < %s
            GROUP BY policy_name
            ORDER BY total_bytes DESC
        """, (start_dt, end_dt))
        policies = cur.fetchall()

        cur.execute("""
            SELECT
                COALESCE(r.policy_name, 'DIRECT') AS policy,
                COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                r.mac_address,
                SUM(r.in_bytes + r.out_bytes) AS total_bytes
            FROM requests r
            LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s
              AND r.policy_name != 'DIRECT' AND r.policy_name IS NOT NULL
            GROUP BY r.policy_name, r.mac_address
            ORDER BY total_bytes DESC
            LIMIT 50
        """, (start_dt, end_dt))
        policy_devices = cur.fetchall()

    return jsonify({
        "policies": [
            {**r, "total_bytes": int(r["total_bytes"]), "download": int(r["download"]), "upload": int(r["upload"]), "requests": int(r["requests"]), "devices": int(r["devices"])}
            for r in policies
        ],
        "policy_devices": [{**r, "total_bytes": int(r["total_bytes"])} for r in policy_devices],
    })


@bp.route("/api/domain/<path:host>")
def api_domain(host):
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
    with db.cursor() as cur:
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
            WHERE r.remote_host = %s AND r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY total_bytes DESC
        """, (host, start_dt, end_dt))
        devices = cur.fetchall()

        cur.execute("""
            SELECT
                SUM(in_bytes + out_bytes) AS total_bytes,
                SUM(in_bytes) AS download,
                SUM(out_bytes) AS upload,
                COUNT(*) AS requests,
                COUNT(DISTINCT mac_address) AS device_count
            FROM requests
            WHERE remote_host = %s AND start_date >= %s AND start_date < %s
        """, (host, start_dt, end_dt))
        summary = cur.fetchone()

    return jsonify({
        "host": host,
        "summary": {k: int(v or 0) for k, v in summary.items()} if summary else {},
        "devices": [
            {**r, "total_bytes": int(r["total_bytes"]), "download": int(r["download"]), "upload": int(r["upload"]), "requests": int(r["requests"])}
            for r in devices
        ],
    })


@bp.route("/api/policy_groups")
def api_policy_groups():
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    rule_map = get_rule_map()
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT
                rule,
                CASE WHEN policy_name IS NULL OR policy_name = 'DIRECT' THEN 'DIRECT'
                     WHEN policy_name IN ('REJECT', 'REJECT-DROP') THEN 'REJECT'
                     ELSE 'PROXY' END AS policy_type,
                SUM(in_bytes + out_bytes) AS total_bytes,
                SUM(in_bytes)             AS download,
                SUM(out_bytes)            AS upload,
                COUNT(*)                  AS requests,
                COUNT(DISTINCT mac_address) AS devices
            FROM requests
            WHERE start_date >= %s AND start_date < %s
            GROUP BY rule, policy_type
        """, (start_dt, end_dt))
        rows = cur.fetchall()

    group_agg = {}
    for row in rows:
        policy_type = row["policy_type"]
        if policy_type == "DIRECT":
            group = "🎯 直连流量"
        elif policy_type == "REJECT":
            group = "🛑 拦截/拒绝"
        else:
            rule_str = row["rule"] or "未知规则"
            group = rule_map.get(rule_str, rule_str)
        if group not in group_agg:
            group_agg[group] = {
                "policy_group": group,
                "total_bytes": 0,
                "download": 0,
                "upload": 0,
                "requests": 0,
                "devices": 0,
            }
        group_agg[group]["total_bytes"] += int(row["total_bytes"])
        group_agg[group]["download"] += int(row["download"])
        group_agg[group]["upload"] += int(row["upload"])
        group_agg[group]["requests"] += int(row["requests"])
        group_agg[group]["devices"] += int(row["devices"])

    result = sorted(
        group_agg.values(),
        key=lambda item: item["total_bytes"],
        reverse=True,
    )
    return jsonify(list(result))


@bp.route("/api/policy_group/<path:name>")
def api_policy_group_detail(name):
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    rule_map = get_rule_map()
    reverse_map = {}
    for rule_key, group_name in rule_map.items():
        reverse_map.setdefault(group_name, set()).add(rule_key)

    rules = tuple(sorted(reverse_map.get(name, set())))
    if name not in {"🎯 直连流量", "🛑 拦截/拒绝"} and not rules:
        return jsonify({"policy_group": name, "domains": [], "devices": []})

    # Build filter clause based on group type
    if name == "🎯 直连流量":
        where_filter = "AND (r.policy_name IS NULL OR r.policy_name = 'DIRECT')"
        params = (start_dt, end_dt)
    elif name == "🛑 拦截/拒绝":
        where_filter = "AND r.policy_name IN ('REJECT', 'REJECT-DROP')"
        params = (start_dt, end_dt)
    else:
        placeholders = ",".join(["%s"] * len(rules))
        where_filter = f"AND r.rule IN ({placeholders}) AND r.policy_name != 'DIRECT' AND r.policy_name IS NOT NULL"
        params = (start_dt, end_dt, *rules)

    db = get_request_db()
    with db.cursor() as cur:
        cur.execute(f"""
            SELECT r.remote_host AS host,
                   SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                   SUM(r.in_bytes) AS download, SUM(r.out_bytes) AS upload,
                   COUNT(*) AS requests
            FROM requests r
            WHERE r.start_date >= %s AND r.start_date < %s {where_filter}
              AND r.remote_host IS NOT NULL AND r.remote_host != ''
            GROUP BY r.remote_host ORDER BY total_bytes DESC LIMIT 50
        """, params)
        domains = cur.fetchall()

        cur.execute(f"""
            SELECT COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                   r.mac_address,
                   SUM(r.in_bytes + r.out_bytes) AS total_bytes, COUNT(*) AS requests
            FROM requests r LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s {where_filter}
            GROUP BY r.mac_address ORDER BY total_bytes DESC
        """, params)
        devices = cur.fetchall()

        cur.execute(f"""
            SELECT COALESCE(SUM(r.in_bytes + r.out_bytes), 0) AS total_bytes,
                   COALESCE(SUM(r.in_bytes), 0) AS download,
                   COALESCE(SUM(r.out_bytes), 0) AS upload, COUNT(*) AS requests
            FROM requests r
            WHERE r.start_date >= %s AND r.start_date < %s {where_filter}
        """, params)
        summary = cur.fetchone()

    return jsonify({
        "policy_group": name,
        "summary": {k: int(v or 0) for k, v in summary.items()} if summary else {},
        "domains": [
            {**r, "total_bytes": int(r["total_bytes"]), "download": int(r["download"]), "upload": int(r["upload"]), "requests": int(r["requests"])}
            for r in domains
        ],
        "devices": [{**r, "total_bytes": int(r["total_bytes"]), "requests": int(r["requests"])} for r in devices],
    })


@bp.route("/api/devices_list")
def api_devices_list():
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT d.mac_address, d.name, d.vendor, d.current_ip,
                   d.dhcp_hostname, d.dns_name
            FROM devices d
            ORDER BY COALESCE(d.name, d.dhcp_hostname, d.mac_address)
        """)
        devices = cur.fetchall()
    return jsonify(devices)


@bp.route("/api/devices")
def api_devices():
    range_info = parse_range()
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
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
            WHERE r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY total_bytes DESC
        """, (start_dt, end_dt))
        devices = cur.fetchall()

    return jsonify([
        {
            **r,
            "total_bytes": int(r["total_bytes"]),
            "download": int(r["download"]),
            "upload": int(r["upload"]),
            "requests": int(r["requests"]),
            "proxy_bytes": int(r["proxy_bytes"]),
            "direct_bytes": int(r["direct_bytes"]),
        }
        for r in devices
    ])
