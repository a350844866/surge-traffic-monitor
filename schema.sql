CREATE DATABASE IF NOT EXISTS surge_traffic CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE surge_traffic;

-- 细粒度每请求数据（来自 /v1/requests/recent API）
CREATE TABLE IF NOT EXISTS requests (
    id                BIGINT UNSIGNED NOT NULL,
    start_date        DATETIME(3) NOT NULL,
    completed_date    DATETIME(3) NULL,
    status            VARCHAR(20) NOT NULL DEFAULT 'Active',
    failed            TINYINT(1) NOT NULL DEFAULT 0,
    method            VARCHAR(20) NOT NULL DEFAULT '',
    url               VARCHAR(2048) NOT NULL DEFAULT '',
    remote_host       VARCHAR(512) NULL,
    remote_address    VARCHAR(45) NULL,
    source_address    VARCHAR(45) NOT NULL DEFAULT '',
    source_port       INT UNSIGNED NOT NULL DEFAULT 0,
    mac_address       VARCHAR(17) NULL,
    rule              VARCHAR(255) NULL,
    policy_name       VARCHAR(100) NULL,
    original_policy   VARCHAR(100) NULL,
    interface         VARCHAR(20) NULL,
    in_bytes          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    out_bytes         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    rejected          TINYINT(1) NOT NULL DEFAULT 0,
    notes_json        JSON NULL,
    timing_json       JSON NULL,
    collected_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, start_date),
    INDEX idx_start_date (start_date),
    INDEX idx_mac_date (mac_address, start_date),
    INDEX idx_remote_host (remote_host(128)),
    INDEX idx_policy_date (policy_name, start_date),
    INDEX idx_source_addr (source_address, start_date)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED
  PARTITION BY RANGE (TO_DAYS(start_date)) (
    PARTITION p202603 VALUES LESS THAN (TO_DAYS('2026-04-01')),
    PARTITION p202604 VALUES LESS THAN (TO_DAYS('2026-05-01')),
    PARTITION p202605 VALUES LESS THAN (TO_DAYS('2026-06-01')),
    PARTITION p202606 VALUES LESS THAN (TO_DAYS('2026-07-01')),
    PARTITION p_future VALUES LESS THAN MAXVALUE
  );

-- 每日聚合数据（来自 Surge SQLite，无损安全网）
CREATE TABLE IF NOT EXISTS daily_traffic (
    id              BIGINT UNSIGNED AUTO_INCREMENT,
    traffic_date    DATE NOT NULL,
    host            VARCHAR(512) NOT NULL,
    device_path     VARCHAR(512) NOT NULL DEFAULT '',
    policy          VARCHAR(100) NOT NULL DEFAULT '',
    interface       VARCHAR(20) NULL,
    up_bytes        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    down_bytes      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_bytes     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    request_count   INT UNSIGNED NOT NULL DEFAULT 0,
    synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE INDEX uk_date_host_device_policy (traffic_date, host(128), device_path(128), policy),
    INDEX idx_date (traffic_date),
    INDEX idx_device_date (device_path(128), traffic_date),
    INDEX idx_host_date (host(128), traffic_date)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED;

-- 设备名称映射（来自 /v1/devices）
CREATE TABLE IF NOT EXISTS devices (
    mac_address     VARCHAR(64) NOT NULL PRIMARY KEY,
    name            VARCHAR(255) NULL,
    vendor          VARCHAR(255) NULL,
    dhcp_hostname   VARCHAR(255) NULL,
    dns_name        VARCHAR(255) NULL,
    current_ip      VARCHAR(45) NULL,
    last_seen       DATETIME NULL,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 采集状态跟踪
CREATE TABLE IF NOT EXISTS collector_state (
    key_name    VARCHAR(50) PRIMARY KEY,
    value       VARCHAR(255) NOT NULL,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO collector_state (key_name, value) VALUES
    ('last_request_id', '0'),
    ('last_sqlite_date', '20260321'),
    ('last_device_sync', '0');

-- 便捷视图：requests JOIN devices
CREATE OR REPLACE VIEW request_details AS
SELECT
    r.id,
    r.start_date,
    r.completed_date,
    r.status,
    r.failed,
    r.method,
    r.url,
    r.remote_host,
    r.remote_address,
    r.source_address,
    r.mac_address,
    r.rule,
    r.policy_name,
    r.original_policy,
    r.interface,
    r.in_bytes,
    r.out_bytes,
    r.rejected,
    COALESCE(d.name, d.dhcp_hostname, d.dns_name, r.mac_address, r.source_address) AS device_name,
    d.vendor AS device_vendor
FROM requests r
LEFT JOIN devices d ON r.mac_address = d.mac_address;
