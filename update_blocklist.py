#!/usr/bin/env python3
"""
Download and update local domain blocklists.
Run daily via systemd timer (surge-blocklist-update.timer).

Sources:
  - URLhaus (abuse.ch): known malware distribution domains  → HIGH
  - OISD Big:           broad blocklist (malware/phishing/tracking) → LOW
"""

import os
import sys
import logging
import requests

sys.path.insert(0, os.path.dirname(__file__))
from db import get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("blocklist")

SOURCES = [
    {
        "name":     "urlhaus",
        "url":      "https://urlhaus.abuse.ch/downloads/hostfile/",
        "format":   "hosts",   # "127.0.0.1 domain" per line
        "severity": "high",
        "reason":   "URLhaus: 已知恶意软件分发域名",
    },
    {
        "name":     "stevenblack",
        "url":      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format":   "hosts",   # "0.0.0.0 domain" per line
        "severity": "low",
        "reason":   "StevenBlack 黑名单（广告/追踪/恶意域名）",
    },
]


def _parse(content, fmt):
    domains = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "hosts":
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                d = parts[1].lower()
                if d not in ("localhost", "localhost.localdomain", "0.0.0.0"):
                    domains.append(d)
        else:
            d = line.lower().rstrip(".")
            if d:
                domains.append(d)
    return domains


def update_source(db, src):
    log.info(f"Downloading {src['name']} ...")
    try:
        resp = requests.get(
            src["url"], timeout=90,
            headers={"User-Agent": "surge-traffic-monitor/1.0 (home network)"},
        )
        resp.raise_for_status()
    except Exception as e:
        log.error(f"{src['name']} download failed: {e}")
        return 0

    domains = _parse(resp.text, src["format"])
    log.info(f"{src['name']}: {len(domains)} domains parsed")

    unique_domains = list(dict.fromkeys(domains))
    batch = 2000
    total = 0
    sql = (
        "INSERT IGNORE INTO domain_blocklist (domain, source, severity, reason) "
        "VALUES (%s,%s,%s,%s)"
    )
    with db.cursor() as cur:
        cur.execute("DELETE FROM domain_blocklist WHERE source=%s", (src["name"],))
        for i in range(0, len(unique_domains), batch):
            rows = [
                (d, src["name"], src["severity"], src["reason"])
                for d in unique_domains[i:i + batch]
            ]
            cur.executemany(sql, rows)
            total += len(rows)
    db.commit()

    log.info(f"{src['name']}: {total} rows inserted")
    return total


def main():
    db = get_db()
    try:
        grand_total = 0
        for src in SOURCES:
            grand_total += update_source(db, src)
        log.info(f"Blocklist update complete: {grand_total} total domains")
    finally:
        db.close()


if __name__ == "__main__":
    main()
