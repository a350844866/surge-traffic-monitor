#!/usr/bin/env python3
"""
Shared MySQL connection helpers with pooling and retry support.
"""

import logging
import time

import pymysql
import pymysql.cursors
from dbutils.pooled_db import PooledDB

import config

log = logging.getLogger("db")

_pool = None


def _create_pool():
    mincached = max(config.DB_POOL_MIN_CACHED, 0)
    maxcached = max(config.DB_POOL_MAX_CACHED, mincached)
    maxconnections = max(config.DB_POOL_MAX_CONNECTIONS, maxcached, 1)
    return PooledDB(
        creator=pymysql,
        maxconnections=maxconnections,
        mincached=mincached,
        maxcached=maxcached,
        blocking=True,
        ping=1,
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASS,
        database=config.MYSQL_DB,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=config.DB_CONNECT_TIMEOUT,
        autocommit=False,
    )


def _get_pool():
    global _pool
    if _pool is None:
        _pool = _create_pool()
    return _pool


def get_db():
    last_error = None
    attempts = max(config.DB_CONNECT_RETRIES, 1)
    for attempt in range(1, attempts + 1):
        try:
            return _get_pool().connection()
        except Exception as exc:  # pragma: no cover - depends on environment
            last_error = exc
            if attempt >= attempts:
                break
            log.warning(
                "MySQL connection failed (attempt %s/%s): %s",
                attempt,
                attempts,
                exc,
            )
            time.sleep(max(config.DB_CONNECT_RETRY_DELAY, 0))
    raise last_error
