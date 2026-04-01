#!/usr/bin/env python3
"""
Upgrade an existing Surge Traffic Collector deployment in place.

What it does:
1. Creates newly introduced tables if missing.
2. Adds missing columns and indexes to existing tables.
3. Seeds collector_state defaults when absent.
4. Ensures request partitions exist for future months.
"""

import logging

import config
from db import get_db
from ensure_request_partitions import ensure_request_partitions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("upgrade")


def _fetch_columns(cur, table_name):
    cur.execute(
        """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        """,
        (config.MYSQL_DB, table_name),
    )
    return {row["COLUMN_NAME"] for row in cur.fetchall()}


def _fetch_indexes(cur, table_name):
    cur.execute(
        """
        SELECT INDEX_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        """,
        (config.MYSQL_DB, table_name),
    )
    return {row["INDEX_NAME"] for row in cur.fetchall()}


def _column_exists(cur, table_name, column_name):
    return column_name in _fetch_columns(cur, table_name)


def _index_exists(cur, table_name, index_name):
    return index_name in _fetch_indexes(cur, table_name)


def _add_column(cur, table_name, column_name, ddl):
    if _column_exists(cur, table_name, column_name):
        return False
    cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {ddl}")
    log.info("added column %s.%s", table_name, column_name)
    return True


def _add_index(cur, table_name, index_name, ddl):
    if _index_exists(cur, table_name, index_name):
        return False
    cur.execute(f"ALTER TABLE {table_name} ADD {ddl}")
    log.info("added index %s.%s", table_name, index_name)
    return True


def _ensure_new_tables(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trusted_parent_domains (
            id        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            pattern   VARCHAR(255) NOT NULL,
            reason    VARCHAR(512) NOT NULL DEFAULT '',
            added_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX uk_pattern (pattern)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trusted_asns (
            id        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            asn       VARCHAR(32) NOT NULL,
            org_name  VARCHAR(255) NOT NULL DEFAULT '',
            reason    VARCHAR(512) NOT NULL DEFAULT '',
            added_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX uk_asn (asn)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_asn_cache (
            ip         VARCHAR(45) NOT NULL PRIMARY KEY,
            asn        VARCHAR(32) NOT NULL DEFAULT '',
            org        VARCHAR(255) NOT NULL DEFAULT '',
            country    VARCHAR(64) NOT NULL DEFAULT '',
            queried_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_queried_at (queried_at),
            INDEX idx_asn (asn)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
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


def _upgrade_requests(cur):
    _add_index(
        cur,
        "requests",
        "idx_remote_host_date",
        "INDEX idx_remote_host_date (remote_host(128), start_date)",
    )


def _upgrade_suspicious_domains(cur):
    _add_column(cur, "suspicious_domains", "active_days", "active_days INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "consecutive_days", "consecutive_days INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "last_active_date", "last_active_date DATE NULL")
    _add_column(cur, "suspicious_domains", "requests_7d", "requests_7d INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "requests_prev_7d", "requests_prev_7d INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "bytes_7d", "bytes_7d BIGINT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "device_count_7d", "device_count_7d INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "persistence_score", "persistence_score INT UNSIGNED NOT NULL DEFAULT 0")
    _add_column(cur, "suspicious_domains", "stats_updated_at", "stats_updated_at DATETIME NULL")
    _add_index(
        cur,
        "suspicious_domains",
        "idx_persistence",
        "INDEX idx_persistence (dismissed, persistence_score)",
    )


def _upgrade_collector_state(cur):
    cur.execute(
        """
        INSERT IGNORE INTO collector_state (key_name, value) VALUES
            ('last_request_id', '0'),
            ('last_sqlite_date', '20260321'),
            ('last_device_sync', '0')
        """
    )


def main():
    db = get_db()
    try:
        with db.cursor() as cur:
            _ensure_new_tables(cur)
            _upgrade_requests(cur)
            _upgrade_suspicious_domains(cur)
            _upgrade_collector_state(cur)
        db.commit()

        created_partitions = ensure_request_partitions(db)
        if created_partitions:
            log.info("created request partitions: %s", ", ".join(created_partitions))
        else:
            log.info("request partitions already up to date")
        log.info("upgrade complete")
    finally:
        db.close()


if __name__ == "__main__":
    main()
