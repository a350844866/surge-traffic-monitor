#!/usr/bin/env python3
"""
Ensure future monthly partitions exist for the requests table.
Run this monthly via cron or a systemd timer.
"""

import logging
from datetime import date

import config
from db import get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("partitions")


def _month_start(day):
    return date(day.year, day.month, 1)


def _add_months(day, months):
    month_index = (day.year * 12 + day.month - 1) + months
    year = month_index // 12
    month = month_index % 12 + 1
    return date(year, month, 1)


def ensure_request_partitions(db, months_ahead=None):
    months_ahead = max(months_ahead or config.REQUEST_PARTITION_MONTHS_AHEAD, 1)
    base_month = _month_start(date.today())

    with db.cursor() as cur:
        cur.execute(
            """
            SELECT PARTITION_NAME
            FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'requests'
              AND PARTITION_NAME IS NOT NULL
            """,
            (config.MYSQL_DB,),
        )
        existing = {row["PARTITION_NAME"] for row in cur.fetchall()}

    if "p_future" not in existing:
        raise RuntimeError("requests table is missing p_future partition")

    created = []
    with db.cursor() as cur:
        for offset in range(months_ahead):
            month_start = _add_months(base_month, offset)
            partition_name = f"p{month_start:%Y%m}"
            if partition_name in existing:
                continue

            next_month = _add_months(month_start, 1)
            cur.execute(
                f"""
                ALTER TABLE requests REORGANIZE PARTITION p_future INTO (
                    PARTITION {partition_name} VALUES LESS THAN (TO_DAYS('{next_month.isoformat()}')),
                    PARTITION p_future VALUES LESS THAN MAXVALUE
                )
                """
            )
            created.append(partition_name)
            existing.add(partition_name)

    db.commit()
    return created


def drop_old_partitions(db, keep_months=None):
    """Drop monthly partitions older than keep_months.

    Set REQUEST_RETENTION_MONTHS in config (0 = disabled, keep all data).
    """
    keep_months = keep_months if keep_months is not None else config.REQUEST_RETENTION_MONTHS
    if keep_months <= 0:
        return []

    cutoff = _add_months(_month_start(date.today()), -keep_months)
    cutoff_name = f"p{cutoff:%Y%m}"

    with db.cursor() as cur:
        cur.execute(
            """
            SELECT PARTITION_NAME
            FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = %s
              AND TABLE_NAME = 'requests'
              AND PARTITION_NAME IS NOT NULL
            """,
            (config.MYSQL_DB,),
        )
        existing = {row["PARTITION_NAME"] for row in cur.fetchall()}

    dropped = []
    for pname in sorted(existing):
        if pname == "p_future" or not pname.startswith("p20"):
            continue
        if pname < cutoff_name:
            with db.cursor() as cur:
                cur.execute(f"ALTER TABLE requests DROP PARTITION {pname}")
            dropped.append(pname)

    if dropped:
        db.commit()
    return dropped


def main():
    db = get_db()
    try:
        created = ensure_request_partitions(db)
        if created:
            log.info("created request partitions: %s", ", ".join(created))
        else:
            log.info("request partitions already cover the configured future window")

        dropped = drop_old_partitions(db)
        if dropped:
            log.info("dropped old partitions: %s", ", ".join(dropped))
        elif config.REQUEST_RETENTION_MONTHS > 0:
            log.info("no partitions old enough to drop (retention: %d months)", config.REQUEST_RETENTION_MONTHS)
    finally:
        db.close()


if __name__ == "__main__":
    main()
