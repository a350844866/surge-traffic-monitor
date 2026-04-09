#!/usr/bin/env python3
"""
Suspicious domain detector for Surge Traffic Monitor.
Two detection modes:
  - heuristic: fast rule-based checks on new domains (runs every collector cycle)
  - blocklist: local domain blocklist lookup (runs every collector cycle, last 60s window)
"""

import re
import math
import time
import logging
import ipaddress
import threading
from datetime import date, datetime, timedelta

import requests as _req
from db import get_db

log = logging.getLogger("detector")


def _field(row, key, index=0):
    if isinstance(row, dict):
        return row[key]
    return row[index]

# ─── Trusted list cache (loaded from DB, refreshed every 5 min) ───────────────

_trusted_patterns_cache = []   # list of lowercase pattern strings
_trusted_patterns_expires = 0
_trusted_asns_cache = set()    # set of ASN strings like "AS4134"
_trusted_asns_expires = 0
_TRUSTED_CACHE_TTL = 300       # 5 minutes
_trusted_lock = threading.Lock()


def _refresh_trusted_cache(db):
    global _trusted_patterns_cache, _trusted_patterns_expires
    global _trusted_asns_cache, _trusted_asns_expires
    now = time.time()
    if now < _trusted_patterns_expires:
        return
    with _trusted_lock:
        # Double-check after acquiring lock
        if now < _trusted_patterns_expires:
            return
        try:
            with db.cursor() as cur:
                cur.execute("SELECT pattern FROM trusted_parent_domains")
                _trusted_patterns_cache = [r["pattern"].lower() for r in cur.fetchall()]
                cur.execute("SELECT asn FROM trusted_asns")
                _trusted_asns_cache = {r["asn"].upper() for r in cur.fetchall()}
            _trusted_patterns_expires = now + _TRUSTED_CACHE_TTL
            _trusted_asns_expires = now + _TRUSTED_CACHE_TTL
        except Exception as e:
            log.warning(f"Failed to refresh trusted cache: {e}")


def _is_trusted_parent(host, db):
    """Return (True, pattern) if host matches a trusted parent domain pattern."""
    _refresh_trusted_cache(db)
    h = _strip_port(host).lower().rstrip(".")
    for pattern in _trusted_patterns_cache:
        p = pattern.lower()
        if h == p or h.endswith("." + p):
            return True, pattern
    return False, None


def _get_asn_info(ip, db):
    """
    Return ASN info dict {asn, org, country} for an IP address.
    Uses ip_asn_cache table; calls ip-api.com on cache miss.
    Returns None on failure.
    """
    try:
        with db.cursor() as cur:
            cur.execute(
                "SELECT asn, org, country FROM ip_asn_cache WHERE ip=%s"
                " AND queried_at > NOW() - INTERVAL 30 DAY", (ip,)
            )
            row = cur.fetchone()
            if row:
                return row
    except Exception:
        pass

    try:
        resp = _req.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,org,as",
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "asn": (data.get("as") or "").split()[0],   # "AS4134 China..." → "AS4134"
                "org": data.get("org") or data.get("as") or "",
                "country": data.get("country") or "",
            }
            try:
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO ip_asn_cache (ip, asn, org, country) VALUES (%s,%s,%s,%s) AS new "
                        "ON DUPLICATE KEY UPDATE asn=new.asn, org=new.org,"
                        " country=new.country, queried_at=NOW()",
                        (ip, result["asn"], result["org"], result["country"]),
                    )
                db.commit()
            except Exception:
                pass
            return result
    except Exception as e:
        log.debug(f"ASN lookup failed for {ip}: {e}")
    return None

# ─── Safe domain exclusions ───────────────────────────────────────────────────

# Unified safe domain set: both exact matches and suffix matches.
# A host is safe if it equals any entry OR ends with ".<entry>".
_SAFE_DOMAIN_SET = frozenset({
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
    "appleiphonecell.com",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "googlevideo.com", "youtube.com", "ytimg.com", "ggpht.com",
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "windows.com", "live.com",
    "outlook.com", "hotmail.com", "skype.com", "xbox.com", "azure.com",
    "msftconnecttest.com", "msedge.net",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "cloudfront.net", "awsstatic.com",
    "ssl-images-amazon.com",
    # CDN & infrastructure
    "akamaiedge.net", "akamaized.net", "akamaistream.net",
    "fastly.net", "fastlylb.net",
    "cloudflare.com", "cloudflare-dns.com",
    "jsdelivr.net", "unpkg.com",
    # Social / Communication
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net",
    "twitter.com", "twimg.com", "t.co",
    "telegram.org", "t.me",
    "wechat.com",
    # Alibaba / Tencent / Baidu (Chinese)
    "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "alicdn.com",
    "alidns.com", "alibaba.com", "alibabacloud.com", "tbcdn.cn",
    "tencent.com", "qq.com", "qpic.cn", "qlogo.cn", "gtimg.com",
    "myqcloud.com", "qcloud.com",
    "baidu.com", "bdstatic.com", "baidustatic.com",
    "jd.com", "jdcloud.com",
    "meituan.com", "eleme.cn",
    "xiaomi.com", "mi.com", "miui.com",
    "bilibili.com", "hdslb.com",
    "iqiyi.com", "youku.com", "iqiyipic.com", "qiyipic.com",
    "mgtv.com", "hunantv.com",
    "weibo.com", "sinaimg.cn", "sina.com.cn",
    "163.com", "126.com", "netease.com", "ndmdhs.com",
    "zhihu.com",
    "bytedance.com", "toutiao.com", "douyin.com", "snssdk.com", "isnssdk.com",
    "kuaishou.com", "gifshow.com",
    # Security / DNS
    "digicert.com", "letsencrypt.org", "sectigo.com", "comodoca.com",
    "1.1.1.1", "8.8.8.8", "114.114.114.114", "223.5.5.5",
    # Misc common
    "github.com", "githubusercontent.com", "githubassets.com",
    "npm.community", "npmjs.com",
    "stackoverflow.com", "stackexchange.com",
    "wikipedia.org",
    "mozilla.org", "firefox.com",
    "ubuntu.com", "debian.org", "centos.org",
    "docker.com", "dockerhub.com",
    "openrouter.ai", "openai.com", "anthropic.com",
    "ntp.org",
    "home-assistant.io",
    "app.link", "app.goo.gl",
    "reddit.com", "redd.it",
    "spotify.com", "scdn.co",
    "twitch.tv",
    "discord.com", "discord.gg", "discordapp.com",
    "linkedin.com",
    "notion.so", "notion.com",
    "slack.com",
    "zoom.us",
    "vercel.app", "vercel.com", "netlify.app", "netlify.com",
    "supabase.co", "supabase.com",
    "plex.direct", "plex.tv",
    "synology.com", "synology.me",
    # Chinese cloud / CDN
    "huaweicloud.com", "hwcloudtest.cn", "volcengine.com", "volces.com",
    "ctyun.cn", "ucloud.cn",
    "cdn20.com", "kunlunsl.com", "chinanetcenter.com",
    # Gaming
    "mihoyo.com", "hoyoverse.com",
})

# Suspicious TLDs — only truly abused free/cheap TLDs
# Removed: .work .link .live .vip .club .cc (too many legitimate uses)
SUSPICIOUS_TLDS = {
    ".tk", ".top", ".xyz", ".buzz", ".gq", ".ml", ".cf", ".ga",
    ".pw", ".click", ".surf", ".icu",
}


def _strip_port(host):
    """Strip port suffix from host, e.g. 'example.com:443' -> 'example.com'."""
    # Handle IPv6 like [::1]:80
    if host.startswith("["):
        bracket_end = host.find("]")
        return host[:bracket_end + 1] if bracket_end != -1 else host
    # For normal hosts/IPs, strip trailing :port
    if ":" in host:
        # Check if it's host:port (not IPv6 without brackets)
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0]
    return host


def _parse_ip_literal(host):
    """Return an ipaddress object for literal IP hosts, otherwise None."""
    h = _strip_port(host).strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def _is_safe(host):
    """Return True if host should be skipped (known safe).

    Matches if host equals any entry in _SAFE_DOMAIN_SET or is a subdomain of one.
    """
    h = _strip_port(host).lower().rstrip(".")
    labels = h.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in _SAFE_DOMAIN_SET:
            return True
    return False


def _shannon_entropy(s):
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _check_heuristics(host):
    """
    Run heuristic checks on a single domain.
    Returns (severity, reason) or (None, None) if not suspicious.
    """
    h = _strip_port(host).lower().rstrip(".")

    # Bare IP address (after port stripping) — skip private/loopback/reserved
    host_ip = _parse_ip_literal(h)
    if host_ip is not None:
        if host_ip.is_private or host_ip.is_loopback or host_ip.is_link_local:
            return None, None
        # Bare IP is common for apps (push, P2P, games); flag as low
        return "low", f"直接 IP 访问（{h}），绕过 DNS 解析"

    labels = h.split(".")
    tld = "." + labels[-1] if labels else ""
    longest_label = max(labels, key=len) if labels else ""

    # High Shannon entropy on longest label (DGA indicator)
    entropy = _shannon_entropy(longest_label)
    if entropy > 4.5 and len(longest_label) >= 8:
        return "high", f"域名熵值过高({entropy:.2f})，疑似 DGA 生成域名"

    # Numeric/hex heavy label — stricter: require pure digits or very high ratio
    # UUID-style subdomains (hex+digits) are common for CDNs, so raise threshold
    if longest_label and len(longest_label) >= 10:
        digit_ratio = sum(1 for c in longest_label if c.isdigit()) / len(longest_label)
        if digit_ratio > 0.8:
            return "high", f"标签中数字占比过高({digit_ratio:.0%})，疑似 DGA 变种"

    # Excessive subdomain depth (possible DNS tunneling)
    if len(labels) > 6:
        return "medium", f"子域名层级过深({len(labels)} 层)，疑似 DNS 隧道"

    # Very long domain (DNS exfiltration)
    if len(h) > 80:
        return "medium", f"域名总长度过长({len(h)} 字符)，疑似 DNS 数据外泄"

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        return "low", f"可疑顶级域名 {tld}，常见于低价/滥用域名"

    return None, None


# ─── Shared query for new domains ────────────────────────────────────────────

def _fetch_new_domains(db, since_dt=None):
    """Fetch domains seen since since_dt that are not yet in suspicious_domains."""
    try:
        with db.cursor() as cur:
            if since_dt is not None:
                cur.execute("""
                    SELECT remote_host,
                           COUNT(*) AS req_count,
                           COUNT(DISTINCT mac_address) AS dev_count
                    FROM requests r
                    LEFT JOIN suspicious_domains sd ON sd.host = r.remote_host
                    WHERE r.start_date >= %s
                      AND r.remote_host IS NOT NULL
                      AND sd.host IS NULL
                    GROUP BY r.remote_host
                """, (since_dt,))
            else:
                cur.execute("""
                    SELECT remote_host,
                           COUNT(*) AS req_count,
                           COUNT(DISTINCT mac_address) AS dev_count
                    FROM requests r
                    LEFT JOIN suspicious_domains sd ON sd.host = r.remote_host
                    WHERE r.start_date >= NOW() - INTERVAL 60 SECOND
                      AND r.remote_host IS NOT NULL
                      AND sd.host IS NULL
                    GROUP BY r.remote_host
                """)
            return cur.fetchall()
    except Exception as e:
        log.warning(f"new domains query failed: {e}")
        return None


# ─── Heuristic detection (runs every collector cycle) ─────────────────────────

def check_new_domains_heuristic(db, prefetched_rows=None):
    """Check domains seen in the last 60s against heuristic rules."""
    if prefetched_rows is None:
        rows = _fetch_new_domains(db)
        if rows is None:
            return 0
    else:
        rows = prefetched_rows

    flagged = 0
    trusted_batch = []
    heuristic_batch = []

    for row in rows:
        host = row["remote_host"]
        if _is_safe(host):
            continue

        # Check trusted parent domain list (DB-managed whitelist)
        trusted, pattern = _is_trusted_parent(host, db)
        if trusted:
            trusted_batch.append((host, row["req_count"], row["dev_count"],
                                  f"[自动白名单] 信任域名: {pattern}"))
            continue

        severity, reason = _check_heuristics(host)
        if severity is None:
            continue

        # For bare IPs: look up ASN and auto-dismiss if from trusted org
        auto_dismiss = False
        auto_notes = None
        h = _strip_port(host).lower()
        if _parse_ip_literal(h) is not None:
            asn_info = _get_asn_info(h, db)
            if asn_info:
                _refresh_trusted_cache(db)
                if asn_info["asn"] and asn_info["asn"].upper() in _trusted_asns_cache:
                    auto_dismiss = True
                    auto_notes = f"[自动白名单] 信任机构: {asn_info['org']} ({asn_info['asn']})"

        heuristic_batch.append((host, reason, severity, row["req_count"], row["dev_count"],
                                int(auto_dismiss), int(auto_dismiss), auto_notes))
        if not auto_dismiss:
            flagged += 1
            log.info(f"heuristic flagged [{severity}] {host}: {reason}")
        else:
            log.info(f"heuristic auto-dismissed [{severity}] {host}: {auto_notes}")

    try:
        if trusted_batch:
            with db.cursor() as cur:
                cur.executemany("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity,
                         request_count, device_count, dismissed, dismissed_at, notes)
                    VALUES (%s, 'heuristic', '信任域名自动白名单', 'low',
                            %s, %s, 1, NOW(), %s)
                    AS new
                    ON DUPLICATE KEY UPDATE last_seen=NOW(),
                        request_count=request_count + new.request_count
                """, trusted_batch)
        if heuristic_batch:
            with db.cursor() as cur:
                cur.executemany("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity,
                         request_count, device_count, dismissed, dismissed_at, notes)
                    VALUES (%s, 'heuristic', %s, %s, %s, %s,
                            %s, IF(%s=1, NOW(), NULL), %s)
                    AS new
                    ON DUPLICATE KEY UPDATE
                        last_seen=NOW(),
                        request_count=request_count + new.request_count,
                        device_count=GREATEST(device_count, new.device_count)
                """, heuristic_batch)
        db.commit()
    except Exception as e:
        log.warning(f"failed to batch insert heuristic flags: {e}")

    return flagged


# ─── Local blocklist detection (runs every collector cycle) ───────────────────

def check_domains_blocklist(db, prefetched_rows=None):
    """
    Check domains seen in the last 60s against the local domain_blocklist table.
    Fast SQL JOIN — no external calls.
    """
    if prefetched_rows is None:
        rows = _fetch_new_domains(db)
        if rows is None:
            return 0
    else:
        rows = prefetched_rows

    if not rows:
        return 0

    # Strip ports; build map stripped_domain → original row
    host_map = {}
    for row in rows:
        stripped = _strip_port(row["remote_host"]).lower().rstrip(".")
        if not _is_safe(row["remote_host"]) and stripped not in host_map:
            host_map[stripped] = row

    if not host_map:
        return 0

    # Batch lookup against local blocklist
    placeholders = ",".join(["%s"] * len(host_map))
    try:
        with db.cursor() as cur:
            cur.execute(
                f"SELECT domain, severity, reason FROM domain_blocklist WHERE domain IN ({placeholders})",
                list(host_map.keys()),
            )
            matches = cur.fetchall()
    except Exception as e:
        log.warning(f"blocklist lookup failed: {e}")
        return 0

    count = 0
    flagged_hosts = set()
    insert_batch = []

    for m in matches:
        row = host_map[m["domain"]]
        host = row["remote_host"]
        flagged_hosts.add(m["domain"])
        insert_batch.append((host, m["reason"], m["severity"],
                             int(row["req_count"]), int(row["dev_count"])))
        count += 1
        log.info(f"blocklist flagged [{m['severity']}] {host}: {m['reason']}")

    # Suffix matching: check parent domains of unflagged hosts
    parent_map = {}  # parent_domain -> [(stripped_domain, original_row)]
    for stripped, row in host_map.items():
        if stripped in flagged_hosts:
            continue
        labels = stripped.split(".")
        for i in range(1, len(labels) - 1):  # skip the TLD alone
            parent = ".".join(labels[i:])
            parent_map.setdefault(parent, []).append((stripped, row))

    if parent_map:
        parent_placeholders = ",".join(["%s"] * len(parent_map))
        try:
            with db.cursor() as cur:
                cur.execute(
                    f"SELECT domain, severity, reason FROM domain_blocklist WHERE domain IN ({parent_placeholders})",
                    list(parent_map.keys()),
                )
                suffix_matches = cur.fetchall()
        except Exception as e:
            log.warning(f"blocklist suffix lookup failed: {e}")
            suffix_matches = []

        for m in suffix_matches:
            for stripped, row in parent_map[m["domain"]]:
                if stripped in flagged_hosts:
                    continue
                flagged_hosts.add(stripped)
                host = row["remote_host"]
                reason = f"{m['reason']}（父域名 {m['domain']} 命中黑名单）"
                insert_batch.append((host, reason, m["severity"],
                                     int(row["req_count"]), int(row["dev_count"])))
                count += 1
                log.info(f"blocklist suffix flagged [{m['severity']}] {host}: {reason}")

    if insert_batch:
        try:
            with db.cursor() as cur:
                cur.executemany("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity, request_count, device_count)
                    VALUES (%s, 'blocklist', %s, %s, %s, %s)
                    AS new
                    ON DUPLICATE KEY UPDATE
                        last_seen=NOW(),
                        reason=new.reason,
                        severity=GREATEST(severity, new.severity),
                        request_count=GREATEST(request_count, new.request_count),
                        device_count=GREATEST(device_count, new.device_count)
                """, insert_batch)
            db.commit()
        except Exception as e:
            log.warning(f"failed to batch insert blocklist flags: {e}")

    return count


# ─── Suspicious domain stats updater ─────────────────────────────────────────

def update_suspicious_stats(db):
    """
    每日一次：为 suspicious_domains 中所有未 dismissed 的条目计算持久性统计，
    写入 active_days / consecutive_days / last_active_date /
         requests_7d / requests_prev_7d / bytes_7d / device_count_7d /
         persistence_score / stats_updated_at。
    """
    today = date.today()
    recent_start_day = today - timedelta(days=6)
    previous_start_day = today - timedelta(days=13)
    recent_start_dt = datetime.combine(recent_start_day, datetime.min.time())
    recent_end_dt = datetime.combine(today + timedelta(days=1), datetime.min.time())
    previous_start_dt = datetime.combine(previous_start_day, datetime.min.time())
    previous_end_dt = recent_start_dt

    with db.cursor() as cur:
        cur.execute("SELECT host FROM suspicious_domains WHERE dismissed = 0")
        hosts = [_field(r, "host", 0) for r in cur.fetchall()]

    if not hosts:
        return 0

    def _batched(items, batch_size):
        for start in range(0, len(items), batch_size):
            yield items[start:start + batch_size]

    # Limit scan to 30 days (active_days score caps at 30)
    scan_start_dt = datetime.combine(today - timedelta(days=29), datetime.min.time())

    stats_by_host = {}
    days_by_host = {host: [] for host in hosts}

    for batch_hosts in _batched(hosts, 200):
        placeholders = ",".join(["%s"] * len(batch_hosts))
        with db.cursor() as cur:
            cur.execute("""
                SELECT
                    remote_host AS host,
                    COALESCE(SUM(CASE WHEN start_date >= %s AND start_date < %s THEN 1 ELSE 0 END), 0) AS req_7d,
                    COALESCE(SUM(CASE WHEN start_date >= %s AND start_date < %s THEN 1 ELSE 0 END), 0) AS req_prev,
                    COALESCE(SUM(CASE WHEN start_date >= %s AND start_date < %s THEN in_bytes + out_bytes ELSE 0 END), 0) AS bytes_7d,
                    COUNT(DISTINCT CASE WHEN start_date >= %s AND start_date < %s THEN mac_address END) AS dev_7d,
                    MAX(start_date) AS last_active_dt,
                    COUNT(DISTINCT DATE(start_date)) AS active_days
                FROM requests
                WHERE remote_host IN (""" + placeholders + """)
                  AND start_date >= %s
                GROUP BY remote_host
            """, (
                recent_start_dt, recent_end_dt,
                previous_start_dt, previous_end_dt,
                recent_start_dt, recent_end_dt,
                recent_start_dt, recent_end_dt,
                *batch_hosts,
                scan_start_dt,
            ))
            for row in cur.fetchall():
                stats_by_host[row["host"]] = row

            cur.execute("""
                SELECT remote_host AS host, DATE(start_date) AS active_day
                FROM requests
                WHERE remote_host IN (""" + placeholders + """)
                  AND start_date >= %s
                GROUP BY remote_host, DATE(start_date)
                ORDER BY remote_host, active_day
            """, (*batch_hosts, scan_start_dt))
            for row in cur.fetchall():
                days_by_host.setdefault(row["host"], []).append(row["active_day"])

    updated = 0
    update_rows = []
    for host in hosts:
        row = stats_by_host.get(host, {})
        req_7d = int(row.get("req_7d") or 0)
        req_prev = int(row.get("req_prev") or 0)
        bytes_7d = int(row.get("bytes_7d") or 0)
        dev_7d = int(row.get("dev_7d") or 0)
        last_active_dt = row.get("last_active_dt")
        last_active = last_active_dt.date() if last_active_dt else None
        active_days = int(row.get("active_days") or 0)

        consecutive_days = 0
        day_rows = days_by_host.get(host, [])
        if day_rows:
            streak = best = 1
            for i in range(1, len(day_rows)):
                if (day_rows[i] - day_rows[i - 1]).days == 1:
                    streak += 1
                    best = max(best, streak)
                else:
                    streak = 1
            consecutive_days = best

        # 3. 持久性评分
        # 活跃天数（每天+2，上限30天=60分）
        score = min(active_days, 30) * 2
        # 最长连续（每天+3，上限14天=42分）
        score += min(consecutive_days, 14) * 3
        # 今日仍活跃 +15
        if last_active == today:
            score += 15
        # 近7天多设备 +10/台（额外设备）
        if dev_7d > 1:
            score += min(dev_7d - 1, 3) * 10
        # 流量上升趋势（近7天 > 前7天的1.5倍）+10
        if req_prev > 0 and req_7d > req_prev * 1.5:
            score += 10
        elif req_prev == 0 and req_7d >= 5:
            # 前7天没有、近7天有5次以上也加分
            score += 5

        update_rows.append((
            active_days,
            consecutive_days,
            last_active,
            req_7d,
            req_prev,
            bytes_7d,
            dev_7d,
            score,
            host,
        ))
        updated += 1

    with db.cursor() as cur:
        cur.executemany("""
            UPDATE suspicious_domains SET
                active_days       = %s,
                consecutive_days  = %s,
                last_active_date  = %s,
                requests_7d       = %s,
                requests_prev_7d  = %s,
                bytes_7d          = %s,
                device_count_7d   = %s,
                persistence_score = %s,
                stats_updated_at  = NOW()
            WHERE host = %s AND dismissed = 0
        """, update_rows)

    db.commit()
    log.info(f"update_suspicious_stats: updated {updated} entries")
    return updated


# ─── Standalone test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    db = get_db()
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    if mode in ("heuristic", "both"):
        n = check_new_domains_heuristic(db)
        print(f"Heuristic: flagged {n}")
    if mode in ("blocklist", "both"):
        n = check_domains_blocklist(db)
        print(f"Blocklist: flagged {n}")
    db.close()
