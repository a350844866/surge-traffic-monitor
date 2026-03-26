#!/usr/bin/env python3
"""
Surge Traffic Collector
Polls Surge HTTP API and syncs SQLite daily files into MySQL.
"""

import os
import sys
import time
import sqlite3
import tempfile
import subprocess
import logging
from datetime import datetime, date, timedelta

import json
import requests
import pymysql
import pymysql.cursors

sys.path.insert(0, os.path.dirname(__file__))
import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("collector")

SURGE_API = f"http://127.0.0.1:{config.SURGE_API_LOCAL_PORT}"
HEADERS = {"X-Key": config.SURGE_API_KEY}


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
        autocommit=False,
    )


def get_state(db, key):
    with db.cursor() as cur:
        cur.execute("SELECT value FROM collector_state WHERE key_name=%s", (key,))
        row = cur.fetchone()
        return row["value"] if row else None


def set_state(db, key, value):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO collector_state (key_name, value) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE value=%s",
            (key, str(value), str(value)),
        )
    db.commit()


# ─── Task 1: Poll /v1/requests/recent ────────────────────────────────────────

def poll_recent_requests(db):
    try:
        resp = requests.get(f"{SURGE_API}/v1/requests/recent", headers=HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning(f"requests/recent failed: {e}")
        return 0

    requests_list = data.get("requests", [])
    if not requests_list:
        return 0

    last_id = int(get_state(db, "last_request_id") or 0)
    new_requests = [r for r in requests_list if r.get("id", 0) > last_id]
    if not new_requests:
        return 0

    rows = []
    for r in new_requests:
        start_ts = r.get("startDate") or r.get("start_date")
        if start_ts:
            start_dt = datetime.fromtimestamp(float(start_ts))
        else:
            start_dt = datetime.now()

        completed_ts = r.get("completedDate") or r.get("completed_date")
        completed_dt = datetime.fromtimestamp(float(completed_ts)) if completed_ts else None

        # Extract source MAC from remoteClientPhysicalAddress
        mac = r.get("remoteClientPhysicalAddress") or r.get("sourcePhysicalAddress")
        if mac:
            mac = mac.upper()

        rows.append({
            "id": r.get("id"),
            "start_date": start_dt,
            "completed_date": completed_dt,
            "status": r.get("status", "Active"),
            "failed": 1 if r.get("failed") else 0,
            "method": (r.get("method") or "")[:20],
            "url": (r.get("URL") or r.get("url") or "")[:2048],
            "remote_host": (r.get("remoteHost") or r.get("remote_host") or "")[:512] or None,
            "remote_address": (r.get("remoteAddress") or r.get("remote_address") or "")[:45] or None,
            "source_address": (r.get("sourceAddress") or r.get("source_address") or "")[:45],
            "source_port": int(r.get("sourcePort") or r.get("source_port") or 0),
            "mac_address": mac[:17] if mac else None,
            "rule": (r.get("rule") or "")[:255] or None,
            "policy_name": (r.get("policyName") or r.get("policy") or "")[:100] or None,
            "original_policy": (r.get("originalPolicy") or r.get("original_policy") or "")[:100] or None,
            "interface": (r.get("interface") or "")[:20] or None,
            "in_bytes": int(r.get("inBytes") or r.get("in_bytes") or 0),
            "out_bytes": int(r.get("outBytes") or r.get("out_bytes") or 0),
            "rejected": 1 if r.get("rejected") else 0,
            "notes_json": json.dumps(r.get("notes")) if r.get("notes") is not None else None,
            "timing_json": json.dumps(r.get("timingRecords")) if r.get("timingRecords") is not None else None,
        })

    if not rows:
        return 0

    sql = """
        INSERT IGNORE INTO requests
            (id, start_date, completed_date, status, failed, method, url,
             remote_host, remote_address, source_address, source_port, mac_address,
             rule, policy_name, original_policy, interface,
             in_bytes, out_bytes, rejected, notes_json, timing_json)
        VALUES
            (%(id)s, %(start_date)s, %(completed_date)s, %(status)s, %(failed)s,
             %(method)s, %(url)s, %(remote_host)s, %(remote_address)s,
             %(source_address)s, %(source_port)s, %(mac_address)s,
             %(rule)s, %(policy_name)s, %(original_policy)s, %(interface)s,
             %(in_bytes)s, %(out_bytes)s, %(rejected)s, %(notes_json)s, %(timing_json)s)
    """
    with db.cursor() as cur:
        cur.executemany(sql, rows)
    db.commit()

    max_id = max(r["id"] for r in rows)
    set_state(db, "last_request_id", max_id)
    log.info(f"requests: inserted {len(rows)} new records, max_id={max_id}")
    return len(rows)


# ─── Task 2: Sync /v1/devices ────────────────────────────────────────────────

def sync_devices(db):
    try:
        resp = requests.get(f"{SURGE_API}/v1/devices", headers=HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning(f"devices sync failed: {e}")
        return 0

    device_list = data.get("devices", [])
    if not device_list:
        return 0

    sql = """
        INSERT INTO devices (mac_address, name, vendor, dhcp_hostname, dns_name, current_ip, last_seen)
        VALUES (%(mac)s, %(name)s, %(vendor)s, %(dhcp_hostname)s, %(dns_name)s, %(current_ip)s, %(last_seen)s)
        ON DUPLICATE KEY UPDATE
            name=VALUES(name), vendor=VALUES(vendor),
            dhcp_hostname=VALUES(dhcp_hostname), dns_name=VALUES(dns_name),
            current_ip=VALUES(current_ip), last_seen=VALUES(last_seen)
    """
    rows = []
    for d in device_list:
        mac = d.get("physicalAddress") or d.get("identifier")
        if not mac:
            continue
        mac = mac.upper()
        last_ts = d.get("dhcpLastSeenTimestamp") or 0
        last_seen_dt = datetime.fromtimestamp(float(last_ts)) if last_ts else None
        # Prefer friendly name; fall back to IP if no name set
        name = d.get("name") or d.get("displayIPAddress") or ""
        # Only store if it looks like an actual name, not an IP
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
            name = None  # Will show device_name as MAC in view
        current_ip = (d.get("dhcpLastIP") or d.get("displayIPAddress") or "")[:45] or None
        rows.append({
            "mac": mac[:64],
            "name": name[:255] if name else None,
            "vendor": (d.get("vendor") or "")[:255] or None,
            "dhcp_hostname": (d.get("dhcpHostname") or "")[:255] or None,
            "dns_name": (d.get("dnsName") or "")[:255] or None,
            "current_ip": current_ip,
            "last_seen": last_seen_dt,
        })

    if rows:
        with db.cursor() as cur:
            cur.executemany(sql, rows)
        db.commit()
        set_state(db, "last_device_sync", int(time.time()))
        log.info(f"devices: upserted {len(rows)} devices")
    return len(rows)


# ─── Task 3: Sync Surge SQLite daily files ───────────────────────────────────

def scp_sqlite(remote_date_str):
    """SCP a daily SQLite file from the Mac mini, return local temp path or None."""
    remote_path = f"{config.SURGE_SQLITE_PATH}/{remote_date_str}.sqlite"
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    # Quote path with spaces for scp
    escaped_path = remote_path.replace(" ", "\\ ")
    cmd = [
        "sshpass", "-p", config.SURGE_SSH_PASS,
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        f"{config.SURGE_SSH_USER}@{config.SURGE_HOST}:{escaped_path}",
        tmp.name,
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        os.unlink(tmp.name)
        return None
    return tmp.name


def import_sqlite(db, local_path, traffic_date):
    """Import one day's SQLite aggregated data into daily_traffic."""
    try:
        conn = sqlite3.connect(local_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM ZSGTRAFFICSTATRECORD")
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        log.warning(f"sqlite read failed for {traffic_date}: {e}")
        return 0

    if not rows:
        return 0

    sql = """
        INSERT INTO daily_traffic
            (traffic_date, host, device_path, policy, interface,
             up_bytes, down_bytes, total_bytes, request_count)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            up_bytes=VALUES(up_bytes),
            down_bytes=VALUES(down_bytes),
            total_bytes=VALUES(total_bytes),
            request_count=VALUES(request_count)
    """
    insert_rows = []
    for r in rows:
        host = r["ZHOST"] or ""
        device_path = r["ZPATH"] or ""
        policy = r["ZPOLICY"] or ""
        interface = r["ZINTERFACE"] or None
        up_bytes = int(r["ZUP"] or 0)
        down_bytes = int(r["ZDOWN"] or 0)
        total_bytes = int(r["ZTOTAL"] or 0)
        request_count = int(r["ZREQUESTCOUNT"] or 0)
        insert_rows.append((
            traffic_date, host[:512], device_path[:512], policy[:100],
            interface, up_bytes, down_bytes, total_bytes, request_count,
        ))

    with db.cursor() as cur:
        cur.executemany(sql, insert_rows)
    db.commit()
    log.info(f"sqlite {traffic_date}: imported {len(insert_rows)} rows")
    return len(insert_rows)


def sync_sqlite_daily(db):
    last_date_str = get_state(db, "last_sqlite_date") or "20260321"
    last_date = datetime.strptime(last_date_str, "%Y%m%d").date()
    today = date.today()

    # Sync from day after last synced up to today
    d = last_date + timedelta(days=1)
    while d <= today:
        date_str = d.strftime("%Y%m%d")
        local_path = scp_sqlite(date_str)
        if local_path:
            import_sqlite(db, local_path, d)
            os.unlink(local_path)
            # Mark as synced (but keep today open for re-sync)
            if d < today:
                set_state(db, "last_sqlite_date", date_str)
        else:
            log.debug(f"sqlite not found for {date_str}, skipping")
        d += timedelta(days=1)

    # Always re-sync today (data is still accumulating)
    today_str = today.strftime("%Y%m%d")
    local_path = scp_sqlite(today_str)
    if local_path:
        import_sqlite(db, local_path, today)
        os.unlink(local_path)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    db = get_db()
    try:
        # Always poll requests (time-sensitive)
        poll_recent_requests(db)

        # Sync devices if interval elapsed
        last_device_sync = int(get_state(db, "last_device_sync") or 0)
        if time.time() - last_device_sync >= config.DEVICE_SYNC_INTERVAL:
            sync_devices(db)

        # Sync SQLite if interval elapsed
        # Use a separate state key for timing
        last_sqlite_sync_key = "last_sqlite_sync_time"
        last_sqlite_sync = int(get_state(db, last_sqlite_sync_key) or 0)
        if time.time() - last_sqlite_sync >= config.SQLITE_SYNC_INTERVAL:
            sync_sqlite_daily(db)
            set_state(db, last_sqlite_sync_key, int(time.time()))

    except Exception as e:
        log.error(f"collector error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
