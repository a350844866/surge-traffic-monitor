import json
import threading

from flask import Blueprint, Response, jsonify, request, stream_with_context

import config
from db import get_db
from web_common import build_time_window, fmt_bytes, get_request_db, parse_range, stream_openrouter
import requests as http_requests

bp = Blueprint("ai", __name__)


@bp.route("/api/ai/device/<path:mac>")
def ai_device(mac):
    model = request.args.get("model", "").strip() or config.OPENROUTER_MODEL
    range_info = parse_range()
    start = range_info["start"]
    end = range_info["end"]
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("SELECT * FROM devices WHERE mac_address = %s", (mac,))
        device = cur.fetchone()
        cur.execute("""
            SELECT
                remote_host AS host,
                SUM(in_bytes + out_bytes) AS total_bytes,
                COUNT(*) AS requests,
                MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL
                         THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE mac_address = %s AND start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY total_bytes DESC
            LIMIT 60
        """, (mac, start_dt, end_dt))
        domains = cur.fetchall()

    if not domains:
        def empty():
            yield "data: " + json.dumps("该时间段内没有流量数据。") + "\n\n"
            yield "data: [DONE]\n\n"

        return Response(
            stream_with_context(empty()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    name = "未知设备"
    if device:
        name = device.get("name") or device.get("dhcp_hostname") or device.get("current_ip") or mac

    domain_lines = "\n".join(
        f"- {d['host']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}  策略:{d['policy']}"
        for d in domains
    )
    prompt = f"""你是一个家庭网络分析助手。以下是设备「{name}」在 {start} 至 {end} 期间访问的域名流量统计（Top 60）：

{domain_lines}

请用中文分析：
1. 这台设备主要在做什么？（推断用途：工作/娱乐/游戏/IoT 等）
2. 流量最大的几个域名属于哪些服务/应用？
3. 有没有值得关注的异常域名或可疑访问？
4. 代理流量和直连流量的比例是否合理？

分析要简洁清晰，使用 Markdown 格式，重点加粗，异常用 ⚠️ 标注。"""

    return stream_openrouter(prompt, model)


def _build_suspicious_prompt(rows):
    entry_lines = []
    for row in rows:
        line = f"[{row['severity'].upper()}] {row['host']}"
        if row.get("org"):
            line += f"  机构:{row['org']}({row['asn']},{row['country']})"
        line += f"  请求:{row['request_count']}次  设备:{row['device_count']}台  原因:{row['reason']}"
        entry_lines.append(line)

    return f"""你是家庭网络安全分析师，审查以下 {len(rows)} 条可疑域名/IP告警。这些告警由启发式规则（高熵域名、裸IP访问、可疑TLD等）自动生成，误报率较高。你的任务是区分真正的威胁和正常流量。

## 告警列表
{chr(10).join(entry_lines)}

## 判断框架

### 直接 DISMISS 的场景（这些是误报）
**CDN / P2P 节点**
- 抖音/TikTok CDN：`*.idouyinvod.com`、`*.ldhy.click`、`*.douyincdn.com`
- 爱奇艺/优酷 P2P CDN：`*.cfogc.com`、`*.tfogc.com`、`*.qiyi.com`，特征是 hash 子域名 + 高端口(>10000)
- 迅雷 P2P：`*.qtaeixd.com`、`*.sandai.net`，高端口(>50000)
- smtcdns / ydycdn / wscdns 等国内 CDN：hash 子域名为正常负载均衡命名

**国内知名平台 SDK / 统计**
- 友盟统计：`*.umeng.com`、`*.umeng.co`、`*.umtrack.com`
- 极光推送 JPush：`*.jpush.cn`、`*.jpush.io`
- 阿里/淘宝统计：`mmstat.com`、`alog.taobao.com`
- 腾讯/微信/QQ：`*.qq.com`、`*.wechat.com`、`*.weixin.qq.com`
- 京东：`*.jddebug.com`、`*.jd.com`
- 各大应用 SDK（Mob、Bugly、TalkingData 等）

**国际大厂**
- Apple/Google/Microsoft/Meta/Amazon 旗下所有服务
- Cloudflare、Akamai、Fastly 等 CDN
- Unity3D、Overwolf、Steam 等游戏平台
- 端口 443/80/8080 + 可信 ASN → 基本无害

**裸 IP 访问（MEDIUM 告警）判断**
- 国内三大运营商 IP（中国电信/联通/移动 106.x/114.x/183.x/121.x/59.x/39.x 等）+ 443/80 端口 → DISMISS（正常 HTTPS，绕过 DNS 很常见）
- 同一 /24 网段多个 IP + 相同非标准端口 → 疑似 P2P 或游戏服务，需结合端口判断
- 境外 IP + 端口 > 10000 且非 443/80 → 优先 KEEP
- 端口像年份（1930/1955/1985/2014 等）+ 多 IP 集群 → 疑似赌博/棋牌 App，KEEP

### 直接 KEEP 的场景（真正可疑）
- 纯数字域名（如 `887765433.uk`）+ 非标端口，无法对应任何已知服务
- hash 子域名 + 完全无名机构 + 非标端口，且不符合已知 P2P CDN 特征
- 仿冒知名品牌的拼写（如 g00gle.com、app1e.com）
- 同一机构多个 IP + 特殊端口组合（1930/1955/1985）→ 疑似赌博类 App
- 境外不知名 VPS + 端口 > 10000 + 请求次数持续增长

## 输出格式
严格按以下 JSON 输出，不要输出任何其他内容：
{{"decisions":[{{"host":"example.com:443","action":"DISMISS","reason":"一句话说明为什么是误报"}},{{"host":"1.2.3.4:9999","action":"KEEP","reason":"一句话说明具体可疑点"}}],"summary":"中文总结：保留了哪些条目、为什么值得关注"}}"""


def _run_ai_review_job(job_id, rows, model):
    entry_count = len(rows)
    prompt = _build_suspicious_prompt(rows)
    db = get_db()

    try:
        try:
            ai_resp = http_requests.post(
                config.OPENROUTER_BASE_URL,
                headers={
                    "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                timeout=120,
            )
            ai_resp.raise_for_status()
            content = ai_resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE ai_review_jobs SET status='error', error_msg=%s, finished_at=NOW() WHERE id=%s",
                    (str(exc)[:1000], job_id),
                )
            db.commit()
            return

        dismissed_list = []
        kept_list = []
        ai_summary = ""
        parse_error = None
        try:
            raw = content
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0]
            parsed = json.loads(raw.strip())
            ai_summary = parsed.get("summary", "")

            for decision in parsed.get("decisions", []):
                host = decision.get("host", "")
                reason = (decision.get("reason") or "")[:900]
                if decision.get("action") == "DISMISS":
                    with db.cursor() as cur:
                        cur.execute(
                            "UPDATE suspicious_domains SET dismissed=1, dismissed_at=NOW(), notes=%s WHERE host=%s AND dismissed=0",
                            ("[AI白名单] " + reason, host),
                        )
                        if cur.rowcount > 0:
                            dismissed_list.append((host, reason))
                else:
                    kept_list.append((host, reason))
            db.commit()
        except Exception as exc:
            parse_error = str(exc)

        md = "## 🤖 AI 安全审查结果\n\n"
        md += f"共审查 **{entry_count}** 条告警\n\n"
        if dismissed_list:
            md += f"### ✅ 已标记安全（{len(dismissed_list)} 条）\n"
            for host, reason in dismissed_list[:30]:
                md += f"- `{host}` — {reason}\n"
            if len(dismissed_list) > 30:
                md += f"- _...及其他 {len(dismissed_list) - 30} 条_\n"
            md += "\n"
        if kept_list:
            md += f"### ⚠️ 保留观察（{len(kept_list)} 条）\n"
            for host, reason in kept_list:
                md += f"- `{host}` — {reason}\n"
            md += "\n"
        if ai_summary:
            md += f"### 总结\n{ai_summary}\n"
        if parse_error:
            md += f"\n> ⚠️ JSON 解析出错: {parse_error}\n> 原始响应片段: {content[:300]}\n"

        with db.cursor() as cur:
            cur.execute(
                "UPDATE ai_review_jobs SET status='done', result_md=%s, dismissed_count=%s, kept_count=%s, finished_at=NOW() WHERE id=%s",
                (md, len(dismissed_list), len(kept_list), job_id),
            )
        db.commit()
    finally:
        db.close()


@bp.route("/api/ai/suspicious/review", methods=["POST"])
def ai_suspicious_review_start():
    model = request.args.get("model", "").strip() or config.OPENROUTER_MODEL
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("SELECT id FROM ai_review_jobs WHERE status='running' ORDER BY id DESC LIMIT 1")
        running = cur.fetchone()
        if running:
            return jsonify({"status": "already_running", "job_id": running["id"]})

        cur.execute("""
            SELECT sd.host, sd.severity, sd.reason, sd.detection_type,
                   sd.request_count, sd.device_count,
                   iac.asn, iac.org, iac.country
            FROM suspicious_domains sd
            LEFT JOIN ip_asn_cache iac
                ON iac.ip = REGEXP_SUBSTR(sd.host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+')
            WHERE sd.dismissed = 0
            ORDER BY FIELD(sd.severity,'high','medium','low'),
                     sd.request_count DESC
            LIMIT 150
        """)
        rows = cur.fetchall()
        if not rows:
            return jsonify({"status": "no_entries"})

        cur.execute(
            "INSERT INTO ai_review_jobs (status, model, entry_count) VALUES ('running', %s, %s)",
            (model, len(rows)),
        )
        job_id = cur.lastrowid
    db.commit()

    thread = threading.Thread(target=_run_ai_review_job, args=(job_id, rows, model), daemon=True)
    thread.start()
    return jsonify({"status": "started", "job_id": job_id})


@bp.route("/api/ai/suspicious/review/status")
def ai_suspicious_review_status():
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT id, status, model, entry_count, dismissed_count, kept_count,
                   error_msg, started_at, finished_at
            FROM ai_review_jobs
            ORDER BY id DESC LIMIT 1
        """)
        row = cur.fetchone()

    if not row:
        return jsonify({"status": "idle"})

    return jsonify({
        "status": row["status"],
        "job_id": row["id"],
        "model": row["model"],
        "entry_count": row["entry_count"],
        "dismissed_count": row["dismissed_count"],
        "kept_count": row["kept_count"],
        "error_msg": row["error_msg"],
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
    })


@bp.route("/api/ai/suspicious/review/result/<int:job_id>")
def ai_suspicious_review_result(job_id):
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute(
            "SELECT result_md, status, dismissed_count, kept_count FROM ai_review_jobs WHERE id=%s",
            (job_id,),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "result_md": row["result_md"] or "",
        "status": row["status"],
        "dismissed_count": row["dismissed_count"],
        "kept_count": row["kept_count"],
    })


@bp.route("/api/ai/overview")
def ai_overview():
    model = request.args.get("model", "").strip() or config.OPENROUTER_MODEL
    range_info = parse_range()
    start = range_info["start"]
    end = range_info["end"]
    start_dt = range_info["start_dt"]
    end_dt = range_info["end_dt"]
    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT
                COALESCE(SUM(in_bytes + out_bytes), 0) AS total_bytes,
                COALESCE(SUM(CASE WHEN policy_name != 'DIRECT' AND policy_name IS NOT NULL
                                 THEN in_bytes + out_bytes ELSE 0 END), 0) AS proxy_bytes,
                COUNT(*) AS requests,
                COUNT(DISTINCT mac_address) AS devices
            FROM requests
            WHERE start_date >= %s AND start_date < %s
        """, (start_dt, end_dt))
        summary = cur.fetchone()

        cur.execute("""
            SELECT
                remote_host AS host,
                SUM(in_bytes + out_bytes) AS total_bytes,
                COUNT(*) AS requests,
                COUNT(DISTINCT mac_address) AS devices,
                MAX(CASE WHEN policy_name = 'DIRECT' OR policy_name IS NULL
                         THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY total_bytes DESC
            LIMIT 40
        """, (start_dt, end_dt))
        top_domains = cur.fetchall()

        cur.execute("""
            SELECT
                COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                r.mac_address,
                SUM(r.in_bytes + r.out_bytes) AS total_bytes,
                COUNT(*) AS requests
            FROM requests r
            LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY total_bytes DESC
            LIMIT 15
        """, (start_dt, end_dt))
        top_devices = cur.fetchall()

    domain_lines = "\n".join(
        f"- {d['host']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}  设备:{d['devices']}台  策略:{d['policy']}"
        for d in top_domains
    )
    device_lines = "\n".join(
        f"- {d['device_name'] or d['mac_address']}  流量:{fmt_bytes(d['total_bytes'])}  请求:{d['requests']}"
        for d in top_devices
    )
    total = int(summary["total_bytes"])
    proxy = int(summary["proxy_bytes"])
    proxy_pct = f"{proxy / total * 100:.1f}%" if total else "0%"

    prompt = f"""你是一个家庭网络安全助手。以下是家庭网络在 {start} 至 {end} 期间的流量摘要：

**整体概况**
- 总流量：{fmt_bytes(total)}，代理占比：{proxy_pct}
- 总请求数：{int(summary['requests'])}，活跃设备：{int(summary['devices'])} 台

**流量最高的域名（Top 40）**
{domain_lines}

**流量最高的设备（Top 15）**
{device_lines}

请用中文分析：
1. 整体网络流量是否正常？有没有异常的流量峰值或可疑设备？
2. 有没有可疑的域名访问（恶意软件、广告跟踪、数据外泄特征等）？
3. 哪些设备流量异常偏高，可能需要排查？
4. 代理流量比例是否合理？
5. 给出 2-3 条具体的安全建议。

分析要简洁专业，使用 Markdown 格式，重点加粗，可疑项用 ⚠️ 标注，严重问题用 🚨 标注。"""

    return stream_openrouter(prompt, model)


@bp.route("/api/ai/overview/hour")
def ai_overview_hour():
    model = request.args.get("model", "").strip() or config.OPENROUTER_MODEL
    time_window = build_time_window(
        request.args.get("date"),
        request.args.get("hour"),
        request.args.get("full_day") == "1",
    )
    date_str = time_window["date"]
    hour = time_window["hour"]
    full_day = time_window["full_day"]
    start_dt = time_window["start_dt"]
    end_dt = time_window["end_dt"]
    sort = request.args.get("sort", "upload")
    sort_by_upload = sort == "upload"

    time_label = f"{date_str} 全天" if full_day else f"{date_str}  {hour:02d}:00 — {hour + 1:02d}:00"
    sort_label = "上传" if sort_by_upload else "下载"

    db = get_request_db()
    with db.cursor() as cur:
        cur.execute("""
            SELECT remote_host AS host,
                   COALESCE(SUM(out_bytes),0) AS upload_bytes,
                   COALESCE(SUM(in_bytes),0)  AS download_bytes,
                   COUNT(*) AS requests,
                   MAX(CASE WHEN policy_name='DIRECT' OR policy_name IS NULL
                            THEN 'DIRECT' ELSE 'PROXY' END) AS policy
            FROM requests
            WHERE start_date >= %s AND start_date < %s
              AND remote_host IS NOT NULL AND remote_host != ''
            GROUP BY remote_host
            ORDER BY IF(%s, SUM(out_bytes), SUM(in_bytes)) DESC
            LIMIT 20
        """, (start_dt, end_dt, sort_by_upload))
        top_domains = cur.fetchall()

        cur.execute("""
            SELECT COALESCE(d.name, d.current_ip, MAX(r.source_address), r.mac_address) AS device_name,
                   COALESCE(SUM(r.out_bytes),0) AS upload_bytes,
                   COALESCE(SUM(r.in_bytes),0)  AS download_bytes,
                   COUNT(*) AS requests
            FROM requests r
            LEFT JOIN devices d ON r.mac_address = d.mac_address
            WHERE r.start_date >= %s AND r.start_date < %s
            GROUP BY r.mac_address
            ORDER BY IF(%s, SUM(r.out_bytes), SUM(r.in_bytes)) DESC
            LIMIT 10
        """, (start_dt, end_dt, sort_by_upload))
        top_devices = cur.fetchall()

        cur.execute("""
            SELECT COALESCE(SUM(out_bytes),0) AS upload_total,
                   COALESCE(SUM(in_bytes),0)  AS download_total,
                   COUNT(*) AS requests,
                   COUNT(DISTINCT mac_address) AS devices
            FROM requests
            WHERE start_date >= %s AND start_date < %s
        """, (start_dt, end_dt))
        summary = cur.fetchone()

    domain_lines = "\n".join(
        f"- {d['host']}  上传:{fmt_bytes(int(d['upload_bytes']))}  下载:{fmt_bytes(int(d['download_bytes']))}  请求:{d['requests']}  策略:{d['policy']}"
        for d in top_domains
    )
    device_lines = "\n".join(
        f"- {d['device_name']}  上传:{fmt_bytes(int(d['upload_bytes']))}  下载:{fmt_bytes(int(d['download_bytes']))}  请求:{d['requests']}"
        for d in top_devices
    )
    focus_extra = (
        "请着重分析上传流量异常：哪些域名/设备上传量偏高？可能是数据同步、备份、还是数据外泄？"
        if sort == "upload"
        else "请着重分析下载流量异常：哪些域名/设备下载量偏高？是正常媒体/更新消耗，还是存在可疑的大量数据拉取？"
    )
    prompt = f"""你是一个家庭网络助手。以下是家庭网络在 {time_label} 的流量数据（按{sort_label}排序）：

**时段概况**
- 总上传：{fmt_bytes(int(summary['upload_total']))}  总下载：{fmt_bytes(int(summary['download_total']))}
- 总请求：{int(summary['requests'])}  活跃设备：{int(summary['devices'])} 台

**{sort_label}最高的域名（Top 20）**
{domain_lines}

**{sort_label}最高的设备（Top 10）**
{device_lines}

请用中文分析：
1. {focus_extra}
2. 流量分布是否正常？有无异常集中的域名或设备？
3. 代理 vs 直连的流量分配是否合理？
4. 给出 1-2 条针对性建议。

分析简洁专业，使用 Markdown，重点加粗，可疑项用 ⚠️ 标注。"""

    return stream_openrouter(prompt, model)
