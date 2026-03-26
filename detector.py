#!/usr/bin/env python3
"""
Suspicious domain detector for Surge Traffic Monitor.
Two detection modes:
  - heuristic: fast rule-based checks on new domains (runs every collector cycle)
  - ai: batch analysis via OpenRouter (runs every AI_SCAN_INTERVAL seconds)
"""

import re
import math
import json
import logging

import requests as http_requests

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


# ─── AI batch detection (runs every AI_SCAN_INTERVAL) ─────────────────────────

def check_domains_ai(db):
    """Batch-analyze recent domains using OpenRouter AI."""
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT remote_host,
                       COUNT(*) AS req_count,
                       COUNT(DISTINCT mac_address) AS dev_count,
                       SUM(in_bytes + out_bytes) AS total_bytes
                FROM requests
                WHERE start_date >= NOW() - INTERVAL 24 HOUR
                  AND remote_host IS NOT NULL
                  AND remote_host NOT IN (
                      SELECT host FROM suspicious_domains
                  )
                GROUP BY remote_host
                ORDER BY req_count DESC
                LIMIT 200
            """)
            rows = cur.fetchall()
    except Exception as e:
        log.warning(f"ai scan query failed: {e}")
        return 0

    if not rows:
        return 0

    # Filter out known safe domains
    candidates = [r for r in rows if not _is_safe(r["remote_host"])]
    if not candidates:
        return 0

    def fmt_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f}{unit}"
            n /= 1024
        return f"{n:.1f}TB"

    domain_lines = "\n".join(
        f"- {r['remote_host']} ({r['req_count']}次请求, {r['dev_count']}台设备, {fmt_bytes(r['total_bytes'] or 0)})"
        for r in candidates[:150]
    )

    prompt = f"""你是家庭网络安全分析师。分析以下域名列表，找出可疑域名（恶意软件C2、追踪器、钓鱼、数据外泄、广告欺诈等）。

注意：这是家庭网络，智能家居设备（小米、海尔等IoT）的正常域名请不要标记。只标记真正有安全风险的域名。

请只返回 JSON 数组，不要有其他文字：
[{{"host": "域名", "reason": "原因（中文）", "severity": "low|medium|high"}}]

如果没有可疑域名，返回 []

域名列表：
{domain_lines}"""

    try:
        resp = http_requests.post(
            config.OPENROUTER_BASE_URL,
            headers={
                "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": config.OPENROUTER_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=60,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        log.warning(f"AI scan API call failed: {e}")
        return 0

    # Parse JSON from AI response (may be wrapped in markdown code blocks)
    json_str = content
    md_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
    if md_match:
        json_str = md_match.group(1)
    else:
        # Try to extract just the array portion
        arr_match = re.search(r"\[[\s\S]*\]", content)
        if arr_match:
            json_str = arr_match.group(0)

    try:
        flagged_list = json.loads(json_str)
        if not isinstance(flagged_list, list):
            flagged_list = []
    except Exception as e:
        log.warning(f"AI response JSON parse failed: {e}\nRaw: {content[:500]}")
        return 0

    # Build a quick lookup for request counts
    req_map = {r["remote_host"]: r for r in candidates}

    count = 0
    for item in flagged_list:
        host = (item.get("host") or "").strip()
        reason = (item.get("reason") or "AI 检测").strip()[:1024]
        severity = item.get("severity", "medium")
        if severity not in ("low", "medium", "high"):
            severity = "medium"
        if not host:
            continue
        stats = req_map.get(host, {})
        try:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO suspicious_domains
                        (host, detection_type, reason, severity, request_count, device_count)
                    VALUES (%s, 'ai', %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        last_seen=NOW(),
                        reason=VALUES(reason),
                        severity=GREATEST(severity, VALUES(severity)),
                        request_count=GREATEST(request_count, VALUES(request_count)),
                        device_count=GREATEST(device_count, VALUES(device_count))
                """, (host, reason, severity,
                      int(stats.get("req_count") or 0),
                      int(stats.get("dev_count") or 0)))
            db.commit()
            count += 1
            log.info(f"AI flagged [{severity}] {host}: {reason}")
        except Exception as e:
            log.warning(f"failed to insert AI flag for {host}: {e}")

    log.info(f"AI scan complete: {count} domains flagged from {len(candidates)} candidates")
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
    if mode in ("ai", "both"):
        n = check_domains_ai(db)
        print(f"AI: flagged {n}")
    db.close()
