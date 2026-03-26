#!/usr/bin/env python3
"""
Suspicious domain detector for Surge Traffic Monitor.
Two detection modes:
  - heuristic: fast rule-based checks on new domains (runs every collector cycle)
  - blocklist: local domain blocklist lookup (runs every collector cycle, last 60s window)
"""

import re
import math
import logging

import config

log = logging.getLogger("detector")

# ─── Safe domain exclusions ───────────────────────────────────────────────────

# Exact match safe domains (lowercase)
SAFE_DOMAINS = {
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
    "appleiphonecell.com", "courier.push.apple.com", "itunes.apple.com",
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
    "cdn.jsdelivr.net", "jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare.com",
    # Social / Communication
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net",
    "twitter.com", "twimg.com", "t.co",
    "telegram.org", "t.me",
    "wechat.com", "weixin.qq.com", "wx.qq.com",
    # Alibaba / Tencent / Baidu (Chinese)
    "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "alicdn.com",
    "alidns.com", "alibaba.com", "alibabacloud.com", "tbcdn.cn",
    "tencent.com", "qq.com", "qpic.cn", "qlogo.cn", "gtimg.com",
    "baidu.com", "bdstatic.com", "baidustatic.com",
    "jd.com", "jdcloud.com",
    "meituan.com", "eleme.cn",
    "xiaomi.com", "mi.com", "miui.com", "io.mi.com",
    "bilibili.com", "hdslb.com",
    "iqiyi.com", "youku.com",
    "weibo.com", "sinaimg.cn", "sina.com.cn",
    "163.com", "126.com", "netease.com",
    "zhihu.com",
    "bytedance.com", "toutiao.com", "douyin.com", "snssdk.com", "isnssdk.com",
    # Security / DNS
    "digicert.com", "ocsp.apple.com", "crl.apple.com",
    "letsencrypt.org", "sectigo.com", "comodoca.com",
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
    "ntp.org", "pool.ntp.org",
    "home-assistant.io",
}

# Safe domain suffixes (match if host ends with these)
SAFE_SUFFIXES = (
    ".apple.com", ".icloud.com", ".mzstatic.com",
    ".google.com", ".googleapis.com", ".gstatic.com", ".googlevideo.com",
    ".youtube.com", ".ytimg.com",
    ".microsoft.com", ".windows.com", ".live.com", ".azure.com", ".msedge.net",
    ".amazon.com", ".amazonaws.com", ".cloudfront.net",
    ".akamaiedge.net", ".akamaized.net", ".fastly.net",
    ".cloudflare.com",
    ".facebook.com", ".fbcdn.net", ".instagram.com", ".whatsapp.com", ".whatsapp.net",
    ".twitter.com", ".twimg.com",
    ".telegram.org",
    ".qq.com", ".weixin.qq.com", ".tencent.com", ".qpic.cn", ".gtimg.com",
    ".myqcloud.com", ".qcloud.com",
    ".baidu.com", ".bdstatic.com",
    ".taobao.com", ".tmall.com", ".alipay.com", ".aliyun.com", ".alicdn.com",
    ".alibaba.com", ".tbcdn.cn",
    ".jd.com",
    ".xiaomi.com", ".mi.com", ".miui.com",
    ".bilibili.com", ".hdslb.com",
    ".mgtv.com", ".hunantv.com",
    ".bytedance.com", ".toutiao.com", ".douyin.com", ".snssdk.com",
    ".163.com", ".126.com", ".netease.com",
    ".github.com", ".githubusercontent.com",
    ".letsencrypt.org",
    ".home-assistant.io",
    ".plex.direct", ".plex.tv",
    ".synology.com", ".synology.me",
    ".ndmdhs.com",  # Netease DRM
)

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".top", ".xyz", ".buzz", ".gq", ".ml", ".cf", ".ga",
    ".pw", ".cc", ".work", ".click", ".link", ".surf", ".icu",
    ".live", ".vip", ".club",
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


def _is_safe(host):
    """Return True if host should be skipped (known safe)."""
    h = _strip_port(host).lower().rstrip(".")
    if h in SAFE_DOMAINS:
        return True
    for suffix in SAFE_SUFFIXES:
        if h.endswith(suffix):
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

    # Bare IP address (after port stripping)
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h):
        return "medium", f"直接 IP 访问（{h}），绕过 DNS 解析"

    labels = h.split(".")
    tld = "." + labels[-1] if labels else ""
    longest_label = max(labels, key=len) if labels else ""

    # High Shannon entropy on longest label (DGA indicator)
    entropy = _shannon_entropy(longest_label)
    if entropy > 3.5 and len(longest_label) >= 8:
        return "high", f"域名熵值过高({entropy:.2f})，疑似 DGA 生成域名"

    # Numeric/hex heavy label
    if longest_label and len(longest_label) >= 8:
        digit_ratio = sum(1 for c in longest_label if c.isdigit()) / len(longest_label)
        if digit_ratio > 0.6:
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


# ─── Heuristic detection (runs every collector cycle) ─────────────────────────

def check_new_domains_heuristic(db):
    """Check domains seen in the last 60s against heuristic rules."""
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT remote_host,
                       COUNT(*) AS req_count,
                       COUNT(DISTINCT mac_address) AS dev_count
                FROM requests
                WHERE start_date >= NOW() - INTERVAL 60 SECOND
                  AND remote_host IS NOT NULL
                  AND remote_host NOT IN (
                      SELECT host FROM suspicious_domains
                  )
                GROUP BY remote_host
            """)
            rows = cur.fetchall()
    except Exception as e:
        log.warning(f"heuristic query failed: {e}")
        return 0

    flagged = 0
    for row in rows:
        host = row["remote_host"]
        if _is_safe(host):
            continue
        severity, reason = _check_heuristics(host)
        if severity is None:
            continue
        try:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity, request_count, device_count)
                    VALUES (%s, 'heuristic', %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        last_seen=NOW(),
                        request_count=request_count + VALUES(request_count),
                        device_count=GREATEST(device_count, VALUES(device_count))
                """, (host, reason, severity, row["req_count"], row["dev_count"]))
            db.commit()
            flagged += 1
            log.info(f"heuristic flagged [{severity}] {host}: {reason}")
        except Exception as e:
            log.warning(f"failed to insert heuristic flag for {host}: {e}")

    return flagged


# ─── Local blocklist detection (runs every collector cycle) ───────────────────

def check_domains_blocklist(db):
    """
    Check domains seen in the last 60s against the local domain_blocklist table.
    Fast SQL JOIN — no external calls.
    """
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT remote_host,
                       COUNT(*) AS req_count,
                       COUNT(DISTINCT mac_address) AS dev_count
                FROM requests
                WHERE start_date >= NOW() - INTERVAL 60 SECOND
                  AND remote_host IS NOT NULL
                  AND remote_host NOT IN (SELECT host FROM suspicious_domains)
                GROUP BY remote_host
            """)
            rows = cur.fetchall()
    except Exception as e:
        log.warning(f"blocklist query failed: {e}")
        return 0

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
    for m in matches:
        row = host_map[m["domain"]]
        host = row["remote_host"]
        try:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity, request_count, device_count)
                    VALUES (%s, 'blocklist', %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        last_seen=NOW(),
                        reason=VALUES(reason),
                        severity=GREATEST(severity, VALUES(severity)),
                        request_count=GREATEST(request_count, VALUES(request_count)),
                        device_count=GREATEST(device_count, VALUES(device_count))
                """, (host, m["reason"], m["severity"],
                      int(row["req_count"]), int(row["dev_count"])))
            db.commit()
            count += 1
            log.info(f"blocklist flagged [{m['severity']}] {host}: {m['reason']}")
        except Exception as e:
            log.warning(f"failed to insert blocklist flag for {host}: {e}")

    return count


# ─── Standalone test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import pymysql
    import pymysql.cursors

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    db = pymysql.connect(
        host=config.MYSQL_HOST, port=config.MYSQL_PORT,
        user=config.MYSQL_USER, password=config.MYSQL_PASS,
        database=config.MYSQL_DB, charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor, autocommit=False,
    )
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    if mode in ("heuristic", "both"):
        n = check_new_domains_heuristic(db)
        print(f"Heuristic: flagged {n}")
    if mode in ("blocklist", "both"):
        n = check_domains_blocklist(db)
        print(f"Blocklist: flagged {n}")
    db.close()
