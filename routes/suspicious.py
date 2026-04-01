import re
import time as _time

from flask import Blueprint, jsonify, request

from db import get_db
from detector import check_domains_blocklist, check_new_domains_heuristic
from web_common import log
import requests as http_requests

bp = Blueprint("suspicious", __name__)


@bp.route("/api/suspicious/count")
def api_suspicious_count():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(severity='high') AS high,
                    SUM(severity='medium') AS medium,
                    SUM(severity='low') AS low,
                    SUM(severity='high' AND persistence_score >= 30) AS confirmed
                FROM suspicious_domains
                WHERE dismissed=0
            """)
            row = cur.fetchone()
    finally:
        db.close()
    return jsonify({
        "count": int(row["total"] or 0),
        "high": int(row["high"] or 0),
        "medium": int(row["medium"] or 0),
        "low": int(row["low"] or 0),
        "confirmed": int(row["confirmed"] or 0),
    })


@bp.route("/api/suspicious")
def api_suspicious():
    show_dismissed = request.args.get("show_dismissed") == "1"
    db = get_db()
    try:
        with db.cursor() as cur:
            where = "" if show_dismissed else "WHERE dismissed=0"
            cur.execute(f"""
                SELECT host, detection_type, reason, severity,
                       first_seen, last_seen, request_count, device_count,
                       dismissed, dismissed_at, notes,
                       active_days, consecutive_days, last_active_date,
                       requests_7d, requests_prev_7d, bytes_7d,
                       device_count_7d, persistence_score
                FROM suspicious_domains
                {where}
                ORDER BY
                    dismissed ASC,
                    persistence_score DESC,
                    FIELD(severity,'high','medium','low'),
                    last_seen DESC
            """)
            rows = cur.fetchall()

        ip_re = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$')
        ips = [ip_re.match(r["host"]).group(1) for r in rows if ip_re.match(r["host"])]
        asn_map = {}
        if ips:
            placeholders = ",".join(["%s"] * len(ips))
            with db.cursor() as cur:
                cur.execute(f"SELECT ip, asn, org, country FROM ip_asn_cache WHERE ip IN ({placeholders})", ips)
                for row in cur.fetchall():
                    asn_map[row["ip"]] = row
    finally:
        db.close()

    result = []
    ip_re = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(:\d+)?$')
    for row in rows:
        item = {
            **row,
            "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            "last_seen": row["last_seen"].isoformat() if row["last_seen"] else None,
            "dismissed_at": row["dismissed_at"].isoformat() if row["dismissed_at"] else None,
            "last_active_date": row["last_active_date"].isoformat() if row["last_active_date"] else None,
            "bytes_7d": int(row["bytes_7d"] or 0),
        }
        match = ip_re.match(row["host"])
        if match and match.group(1) in asn_map:
            info = asn_map[match.group(1)]
            item["ip_org"] = info["org"]
            item["ip_asn"] = info["asn"]
            item["ip_country"] = info["country"]
        result.append(item)
    return jsonify(result)


@bp.route("/api/suspicious/<path:host>/dismiss", methods=["POST"])
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


@bp.route("/api/suspicious/<path:host>/restore", methods=["POST"])
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


@bp.route("/api/suspicious/scan", methods=["POST"])
def api_suspicious_scan():
    db = get_db()
    try:
        heuristic_count = check_new_domains_heuristic(db)
        blocklist_count = check_domains_blocklist(db)
    finally:
        db.close()
    return jsonify({"ok": True, "new_flags": heuristic_count + blocklist_count})


@bp.route("/api/suspicious/enrich-ips", methods=["POST"])
def api_suspicious_enrich_ips():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT
                    REGEXP_SUBSTR(sd.host, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+') AS ip
                FROM suspicious_domains sd
                LEFT JOIN ip_asn_cache iac
                    ON iac.ip = REGEXP_SUBSTR(sd.host, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+')
                   AND iac.queried_at > NOW() - INTERVAL 30 DAY
                WHERE sd.host REGEXP '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+'
                  AND iac.ip IS NULL
            """)
            ips = [row["ip"] for row in cur.fetchall() if row["ip"]]
    except Exception as exc:
        db.close()
        return jsonify({"ok": False, "error": str(exc)}), 500

    enriched = 0
    for index in range(0, len(ips), 100):
        batch = ips[index:index + 100]
        try:
            resp = http_requests.post(
                "http://ip-api.com/batch?fields=status,query,country,org,as",
                json=[{"query": ip} for ip in batch],
                timeout=10,
            )
            for item in resp.json():
                if item.get("status") != "success":
                    continue
                ip = item["query"]
                asn = (item.get("as") or "").split()[0]
                org = item.get("org") or item.get("as") or ""
                country = item.get("country") or ""
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO ip_asn_cache (ip, asn, org, country) VALUES (%s,%s,%s,%s) AS new "
                        "ON DUPLICATE KEY UPDATE asn=new.asn, org=new.org, country=new.country, queried_at=NOW()",
                        (ip, asn, org, country),
                    )
                db.commit()
                enriched += 1
        except Exception as exc:
            log.warning("Batch ASN lookup error: %s", exc)
        if index + 100 < len(ips):
            _time.sleep(1.5)

    try:
        with db.cursor() as cur:
            cur.execute("""
                UPDATE suspicious_domains sd
                JOIN ip_asn_cache iac
                    ON iac.ip = REGEXP_SUBSTR(sd.host, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+')
                JOIN trusted_asns ta ON ta.asn = iac.asn
                SET sd.dismissed = 1,
                    sd.dismissed_at = NOW(),
                    sd.notes = CONCAT('[自动白名单] 信任机构: ', iac.org, ' (', iac.asn, ')')
                WHERE sd.dismissed = 0
                  AND sd.host REGEXP '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+'
            """)
            auto_dismissed = cur.rowcount
        db.commit()
    except Exception as exc:
        log.warning("Auto-dismiss by ASN failed: %s", exc)
        auto_dismissed = 0
    finally:
        db.close()

    return jsonify({"ok": True, "enriched": enriched, "auto_dismissed": auto_dismissed})


@bp.route("/api/trusted/domains", methods=["GET"])
def api_trusted_domains_list():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id, pattern, reason, added_at FROM trusted_parent_domains ORDER BY added_at DESC")
            rows = cur.fetchall()
    finally:
        db.close()
    return jsonify([{**r, "added_at": r["added_at"].isoformat()} for r in rows])


@bp.route("/api/trusted/domains", methods=["POST"])
def api_trusted_domains_add():
    data = request.get_json(force=True, silent=True) or {}
    pattern = (data.get("pattern") or "").strip().lower().lstrip(".")
    reason = (data.get("reason") or "").strip()[:512]
    if not pattern:
        return jsonify({"ok": False, "error": "pattern required"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO trusted_parent_domains (pattern, reason) VALUES (%s, %s) AS new "
                "ON DUPLICATE KEY UPDATE reason=new.reason",
                (pattern, reason),
            )
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True, "pattern": pattern})


@bp.route("/api/trusted/domains/<path:pattern>", methods=["DELETE"])
def api_trusted_domains_delete(pattern):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM trusted_parent_domains WHERE pattern=%s", (pattern,))
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True})


@bp.route("/api/trusted/asns", methods=["GET"])
def api_trusted_asns_list():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT ta.id, ta.asn, ta.org_name, ta.reason, ta.added_at,
                    (SELECT COUNT(*) FROM suspicious_domains sd
                     JOIN ip_asn_cache iac
                         ON iac.ip = REGEXP_SUBSTR(sd.host, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+')
                     WHERE iac.asn = ta.asn AND sd.dismissed=1
                    ) AS dismissed_count
                FROM trusted_asns ta
                ORDER BY ta.added_at DESC
            """)
            rows = cur.fetchall()
    finally:
        db.close()
    return jsonify([{**r, "added_at": r["added_at"].isoformat()} for r in rows])


@bp.route("/api/trusted/asns", methods=["POST"])
def api_trusted_asns_add():
    data = request.get_json(force=True, silent=True) or {}
    asn = (data.get("asn") or "").strip().upper()
    org_name = (data.get("org_name") or "").strip()[:255]
    reason = (data.get("reason") or "").strip()[:512]
    if not asn:
        return jsonify({"ok": False, "error": "asn required"}), 400
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO trusted_asns (asn, org_name, reason) VALUES (%s,%s,%s) AS new "
                "ON DUPLICATE KEY UPDATE org_name=new.org_name, reason=new.reason",
                (asn, org_name, reason),
            )
            cur.execute("""
                UPDATE suspicious_domains sd
                JOIN ip_asn_cache iac
                    ON iac.ip = REGEXP_SUBSTR(sd.host, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+')
                SET sd.dismissed=1, sd.dismissed_at=NOW(),
                    sd.notes=CONCAT('[自动白名单] 信任机构: ', iac.org, ' (', iac.asn, ')')
                WHERE sd.dismissed=0 AND iac.asn=%s
                  AND sd.host REGEXP '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+'
            """, (asn,))
            dismissed = cur.rowcount
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True, "asn": asn, "auto_dismissed": dismissed})


@bp.route("/api/trusted/asns/<asn>", methods=["DELETE"])
def api_trusted_asns_delete(asn):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM trusted_asns WHERE asn=%s", (asn.upper(),))
        db.commit()
    finally:
        db.close()
    return jsonify({"ok": True})
