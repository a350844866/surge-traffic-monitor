"""
Airport management: list / add / delete / refresh proxy subscriptions.

Data lives in /data/sub-store/:
  airports.json      - metadata for every airport
  <name>_surge.txt   - Surge proxy-list file

File serving:
  /sub/<filename>    - serves node files (basic auth required if ?auth=1)
"""

import hmac
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from functools import wraps
from pathlib import Path
from urllib.parse import quote as urlquote

import requests
from flask import (Blueprint, Response, abort, jsonify, render_template,
                   request, send_from_directory)

import config

bp = Blueprint("airports", __name__)
log = logging.getLogger("airports")

SUB_STORE = Path(config.SUB_STORE_PATH)
AIRPORTS_JSON = SUB_STORE / "airports.json"
SUBCONVERTER = config.SUBCONVERTER_URL
SURGE_CONF_INTERNAL = f"{config.SURGE_CONF_DIR}/{config.SURGE_CONF_INTERNAL}"
SURGE_CONF_PUBLIC = f"{config.SURGE_CONF_DIR}/{config.SURGE_CONF_PUBLIC}"
INTERNAL_BASE = config.AIRPORT_INTERNAL_BASE
PUBLIC_BASE = config.AIRPORT_PUBLIC_BASE

FILE_AUTH_USER = config.AIRPORT_FILE_AUTH_USER
FILE_AUTH_PASS = config.AIRPORT_FILE_AUTH_PASS


# ── file serving ───────────────────────────────────────────────
def _check_basic_auth():
    auth = request.authorization
    if auth and hmac.compare_digest(auth.username, FILE_AUTH_USER) \
            and hmac.compare_digest(auth.password, FILE_AUTH_PASS):
        return True
    log.warning("Basic auth failed from %s", request.remote_addr)
    return False


@bp.route("/sub/<filename>")
def serve_node_file(filename):
    """Serve node files. Requires basic auth when accessed externally (via NPM)."""
    if not filename.endswith("_surge.txt"):
        abort(404)
    fpath = (SUB_STORE / filename).resolve()
    if not str(fpath).startswith(str(SUB_STORE.resolve())):
        abort(404)
    if not fpath.exists():
        abort(404)
    # Check if request comes from LAN (no auth needed) or external (auth needed)
    remote = request.remote_addr or ""
    try:
        import ipaddress as _ipa
        is_lan = _ipa.ip_address(remote).is_private
    except ValueError:
        is_lan = False
    if not is_lan and not _check_basic_auth():
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="Subscription"'},
        )
    content = fpath.read_text("utf-8")
    return Response(content, mimetype="text/plain; charset=utf-8")


# ── helpers ────────────────────────────────────────────────────
def _load_airports():
    if AIRPORTS_JSON.exists():
        return json.loads(AIRPORTS_JSON.read_text("utf-8"))
    return {}


def _save_airports(data):
    AIRPORTS_JSON.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), "utf-8"
    )


def _build_subconv_url(raw_url, extra=""):
    encoded = urlquote(raw_url, safe="")
    base = (
        f"{SUBCONVERTER}/sub?target=surge&ver=4"
        f"&url={encoded}"
        "&insert=false"
        "&config=https%3A%2F%2Fraw.githubusercontent.com"
        "%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online.ini"
        "&append_type=false&emoji=true&list=true&tfo=false"
        "&scv=true&fdn=false&expand=true&sort=true&udp=true"
    )
    if extra:
        base += "&" + extra
    return base


def _fetch_nodes(subconv_url):
    resp = requests.get(subconv_url, timeout=30)
    resp.raise_for_status()
    text = resp.text
    text = text.replace(" = hysteria, ", " = hysteria2, ")
    text = re.sub(r",skip-cert-verify", ", skip-cert-verify", text)
    text = re.sub(r",sni=", ", sni=", text)
    lines = [l for l in text.splitlines() if l.strip() and " = " in l]
    return "\n".join(lines) + "\n"


def _write_pass_file():
    """Write SSH password to a secure temp file for sshpass -f."""
    fd = os.open(
        os.path.join(tempfile.gettempdir(), f"_ssh_pw_{os.getpid()}"),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "w") as f:
        f.write(config.SURGE_SSH_PASS)
    return f"/tmp/_ssh_pw_{os.getpid()}"


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "PubkeyAuthentication=no",
    "-o", "GSSAPIAuthentication=no",
]


def _ssh_cmd(cmd_args):
    """Run a command on the remote host via SSH (no shell=True)."""
    pw_file = _write_pass_file()
    try:
        args = [
            "sshpass", "-f", pw_file, "ssh",
            *_SSH_OPTS,
            f"{config.SURGE_SSH_USER}@{config.SURGE_HOST}",
            *cmd_args,
        ]
        r = subprocess.run(args, capture_output=True, timeout=15)
        return r.stdout.decode("utf-8", errors="replace")
    finally:
        os.unlink(pw_file)


def _ssh_read_file(path):
    return _ssh_cmd(["cat", path])


def _ssh_write_file(path, content):
    tmp_local = os.path.join(tempfile.gettempdir(), f"_airport_local_{os.getpid()}.tmp")
    tmp_remote = f"/tmp/_airport_remote_{os.getpid()}.tmp"
    with open(tmp_local, "w", encoding="utf-8") as f:
        f.write(content)
    pw_file = _write_pass_file()
    try:
        scp_args = [
            "sshpass", "-f", pw_file, "scp",
            *_SSH_OPTS,
            tmp_local,
            f"{config.SURGE_SSH_USER}@{config.SURGE_HOST}:{tmp_remote}",
        ]
        subprocess.run(scp_args, timeout=15, check=True)
    finally:
        os.unlink(pw_file)
    _ssh_cmd(["mv", tmp_remote, path])
    os.unlink(tmp_local)


# ── Surge config patching ─────────────────────────────────────
_REGION_FILTERS = [
    ("香港节点", ".*香港.*"),
    ("台湾节点", ".*台湾.*"),
    ("狮城节点", ".*(新加坡|狮城).*"),
    ("日本节点", ".*日本.*"),
    ("美国节点", ".*美国.*"),
    ("韩国节点", ".*韩国.*"),
]

_AGGREGATE_GROUPS = {
    "故障转移": "urltest",
    "二级故障转移": "urltest",
    "🚀 节点选择": "urltest",
    "🚀 手动切换": "select",
    "📲 电报消息": "urltest",
    "💬 OpenAi": "both",
    "📹 油管视频": "urltest",
    "🎥 奈飞视频": "urltest",
    "🏰 迪士尼": "urltest",
    "🤖Gemini": "urltest",
    "🤖Claude": "urltest",
    "TikTok": "urltest",
    "🌍 国外媒体": "urltest",
    "📢 谷歌FCM": "urltest",
    "Ⓜ️ 微软云盘": "urltest",
    "Ⓜ️ 微软服务": "urltest",
    "🍎 苹果服务": "urltest",
    "🎮 游戏平台": "urltest",
    "🐟 漏网之鱼": "both_select",
}

_REGION_GROUPS = {
    "🇭🇰 香港节点": "香港节点",
    "🇯🇵 日本节点": "日本节点",
    "🇺🇲 美国节点": "美国节点",
    "🇨🇳 台湾节点": "台湾节点",
    "🇸🇬 狮城节点": "狮城节点",
    "🇰🇷 韩国节点": "韩国节点",
}


def _insert_ref(line, ref, before):
    for b in before:
        if f", {b}" in line:
            return line.replace(f", {b}", f", {ref}, {b}", 1)
        if f",{b}" in line:
            return line.replace(f",{b}", f", {ref}, {b}", 1)
    return line.rstrip() + f", {ref}"


def _add_to_surge_config(content, name, policy_path, insert_after=None):
    lines = content.split("\n")

    # Build new proxy group lines
    new_groups = [
        f"{name}-select = select, policy-path={policy_path}, "
        f"update-interval=86400, no-alert=0, hidden=0, include-all-proxies=0",
        f"{name}-urltest = smart, policy-path={policy_path}, "
        f"update-interval=86400, no-alert=0, hidden=1, include-all-proxies=0",
    ]
    for region_name, regex in _REGION_FILTERS:
        new_groups.append(
            f"{name}{region_name} = smart, policy-path={policy_path}, "
            f"update-interval=86400, policy-regex-filter={regex}, "
            f"no-alert=1, hidden=1, include-all-proxies=0"
        )
    new_groups.append(
        f"{name}4openAi = select, policy-path={policy_path}, "
        f"update-interval=86400, no-alert=0, hidden=0, include-all-proxies=0"
    )

    # Insert proxy groups after insert_after's 4openAi line, or after last 4openAi
    target_prefix = f"{insert_after}4openAi" if insert_after else None
    result = []
    inserted = False
    last_openai_idx = -1

    for i, line in enumerate(lines):
        if "4openAi" in line and "policy-path=" in line:
            last_openai_idx = i

    for i, line in enumerate(lines):
        result.append(line)
        if not inserted:
            if target_prefix and line.startswith(target_prefix):
                result.extend(new_groups)
                inserted = True
            elif not target_prefix and i == last_openai_idx:
                result.extend(new_groups)
                inserted = True

    # Add to aggregate and region groups
    final = []
    for line in result:
        modified = line

        for prefix, kind in _AGGREGATE_GROUPS.items():
            if not line.startswith(prefix + " ="):
                continue
            if f"{name}-" in line or f"{name}4" in line:
                break
            if kind == "urltest":
                modified = _insert_ref(
                    modified, f"{name}-urltest",
                    ["ppdog-urltest", "ppdog-lowCost-urltest", "DIRECT"],
                )
            elif kind == "select":
                modified = _insert_ref(
                    modified, f"{name}-select",
                    ["ppdog-select", "DIRECT"],
                )
            elif kind == "both":
                modified = _insert_ref(
                    modified, f"{name}-urltest",
                    ["ppdog-urltest", "ppdog-lowCost-urltest", "DIRECT"],
                )
                modified = _insert_ref(
                    modified, f"{name}4openAi",
                    [f"{name}-urltest", "yushe-urltest", "ppdog-urltest"],
                )
            elif kind == "both_select":
                modified = _insert_ref(
                    modified, f"{name}-urltest",
                    ["ppdog-urltest", "ppdog-lowCost-urltest", "DIRECT"],
                )
                modified = _insert_ref(
                    modified, f"{name}-select",
                    ["ppdog-select", "DIRECT"],
                )
            break

        for prefix, region in _REGION_GROUPS.items():
            if not line.startswith(prefix + " ="):
                continue
            ref = f"{name}{region}"
            if ref in line:
                break
            modified = _insert_ref(
                modified, ref,
                [f"ppdog{region}", f"ppdog低倍率{region}", "DIRECT"],
            )
            break

        if "include-other-group=" in line and f"{name}-select" not in line:
            if "👸非港优选" in line or "⚓ 链式底层跳板" in line:
                modified = modified.replace(
                    'ppdog-select"',
                    f'{name}-select, ppdog-select"',
                )

        final.append(modified)

    return "\n".join(final)


def _remove_from_surge_config(content, name):
    lines = content.split("\n")
    result = []
    # Prefixes that belong to this airport's own group definitions
    own_prefixes = [f"{name}-", f"{name}4"]
    for rn, _ in _REGION_FILTERS:
        own_prefixes.append(f"{name}{rn}")

    for line in lines:
        # Skip the airport's own proxy group definitions
        skip = False
        for pfx in own_prefixes:
            if line.startswith(pfx) and "policy-path=" in line:
                skip = True
                break
        if skip:
            continue

        # Remove references from aggregate/region lines
        cleaned = line
        refs = [f"{name}-urltest", f"{name}-select", f"{name}4openAi"]
        for rn, _ in _REGION_FILTERS:
            refs.append(f"{name}{rn}")
        for ref in refs:
            cleaned = cleaned.replace(f", {ref}", "")

        # include-other-group
        cleaned = cleaned.replace(f"{name}-select, ", "")

        result.append(cleaned)
    return "\n".join(result)


# ── API routes ─────────────────────────────────────────────────
@bp.route("/airports")
def airports_page():
    return render_template("airports.html")


@bp.route("/api/airports", methods=["GET"])
def list_airports():
    airports = _load_airports()
    for name, info in airports.items():
        fpath = SUB_STORE / f"{name}_surge.txt"
        if fpath.exists():
            info["file_exists"] = True
            info["file_size"] = fpath.stat().st_size
            info["file_mtime"] = fpath.stat().st_mtime
            info["node_count"] = len(
                [l for l in fpath.read_text("utf-8").splitlines() if l.strip()]
            )
        else:
            info["file_exists"] = False
            info["node_count"] = 0
    return jsonify(airports)


@bp.route("/api/airports", methods=["POST"])
def add_airport():
    data = request.json or {}
    name = data.get("name", "").strip()
    display_name = data.get("display_name", name).strip()
    subscribe_url = data.get("subscribe_url", "").strip()
    auto_update = data.get("auto_update", True)
    insert_after = data.get("insert_after", "").strip()

    if not name or not subscribe_url:
        return jsonify({"error": "name and subscribe_url are required"}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", name):
        return jsonify({"error": "name must start with a letter, alphanumeric only"}), 400

    airports = _load_airports()
    if name in airports:
        return jsonify({"error": f"airport '{name}' already exists"}), 409

    # 1. Fetch nodes
    subconv_url = _build_subconv_url(subscribe_url)
    try:
        node_text = _fetch_nodes(subconv_url)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch nodes: {e}"}), 502

    node_count = len([l for l in node_text.splitlines() if l.strip()])
    if node_count == 0:
        return jsonify({"error": "No valid nodes returned"}), 422

    # 2. Save node file
    fpath = SUB_STORE / f"{name}_surge.txt"
    fpath.write_text(node_text, "utf-8")
    os.chmod(str(fpath), 0o644)

    # 3. Register
    airports[name] = {
        "name": name,
        "display_name": display_name,
        "subscribe_url": subscribe_url,
        "subconverter_url": subconv_url,
        "auto_update": auto_update,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _save_airports(airports)

    # 4. Patch Surge configs
    insert_kw = f"{insert_after}4openAi" if insert_after else None
    errors = []
    for conf_path, base_url in [
        (SURGE_CONF_INTERNAL, f"{INTERNAL_BASE}/{name}_surge.txt"),
        (SURGE_CONF_PUBLIC, f"{PUBLIC_BASE}/{name}_surge.txt"),
    ]:
        try:
            content = _ssh_read_file(conf_path)
            if not content.strip():
                errors.append(f"Could not read {conf_path}")
                continue
            patched = _add_to_surge_config(content, name, base_url, insert_after)
            _ssh_write_file(conf_path, patched)
        except Exception as e:
            errors.append(f"Patch {conf_path}: {e}")

    return jsonify({"ok": True, "name": name, "node_count": node_count, "errors": errors})


@bp.route("/api/airports/<name>", methods=["DELETE"])
def delete_airport(name):
    airports = _load_airports()
    if name not in airports:
        return jsonify({"error": f"airport '{name}' not found"}), 404

    errors = []
    for conf_path in [SURGE_CONF_INTERNAL, SURGE_CONF_PUBLIC]:
        try:
            content = _ssh_read_file(conf_path)
            if content.strip():
                cleaned = _remove_from_surge_config(content, name)
                _ssh_write_file(conf_path, cleaned)
        except Exception as e:
            errors.append(f"Clean {conf_path}: {e}")

    fpath = SUB_STORE / f"{name}_surge.txt"
    if fpath.exists():
        fpath.unlink()

    del airports[name]
    _save_airports(airports)
    return jsonify({"ok": True, "errors": errors})


@bp.route("/api/airports/<name>/refresh", methods=["POST"])
def refresh_airport(name):
    airports = _load_airports()
    if name not in airports:
        return jsonify({"error": f"airport '{name}' not found"}), 404

    info = airports[name]
    url = info.get("subconverter_url") or _build_subconv_url(info["subscribe_url"])
    try:
        node_text = _fetch_nodes(url)
    except Exception as e:
        return jsonify({"error": f"Fetch failed: {e}"}), 502

    node_count = len([l for l in node_text.splitlines() if l.strip()])
    if node_count == 0:
        return jsonify({"error": "No valid nodes returned"}), 422

    fpath = SUB_STORE / f"{name}_surge.txt"
    fpath.write_text(node_text, "utf-8")
    os.chmod(str(fpath), 0o644)

    info["last_refreshed"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _save_airports(airports)
    return jsonify({"ok": True, "node_count": node_count})


# ── Node status via Surge API ─────────────────────────────────
SURGE_API = f"http://127.0.0.1:{config.SURGE_API_LOCAL_PORT}"
SURGE_HEADERS = {"X-Key": config.SURGE_API_KEY}


@bp.route("/api/airports/node-status")
def airport_node_status():
    """Return per-airport node status (latency, availability) from Surge API."""
    airports = _load_airports()
    if not airports:
        return jsonify({})

    # Fetch policy groups and benchmark results from Surge in parallel
    try:
        groups_resp = requests.get(
            f"{SURGE_API}/v1/policy_groups", headers=SURGE_HEADERS, timeout=5,
        )
        groups_resp.raise_for_status()
        groups = groups_resp.json()
    except Exception as e:
        log.warning("Failed to fetch policy_groups: %s", e)
        return jsonify({"error": f"Surge API unavailable: {e}"}), 502

    try:
        bench_resp = requests.get(
            f"{SURGE_API}/v1/policies/benchmark_results",
            headers=SURGE_HEADERS, timeout=5,
        )
        bench_resp.raise_for_status()
        benchmarks = bench_resp.json()
    except Exception as e:
        log.warning("Failed to fetch benchmark_results: %s", e)
        benchmarks = {}

    result = {}
    for name in airports:
        # Each airport has a urltest group: <name>-urltest
        group_key = f"{name}-urltest"
        nodes = groups.get(group_key, [])
        if not nodes:
            # Try select group as fallback
            nodes = groups.get(f"{name}-select", [])

        node_list = []
        counts = {"excellent": 0, "good": 0, "pass": 0, "timeout": 0}
        total = 0

        for n in nodes:
            if n.get("isGroup"):
                continue
            total += 1
            line_hash = n.get("lineHash", "")
            bench = benchmarks.get(line_hash, {})
            latency = bench.get("lastTestScoreInMS", -1)
            error_msg = bench.get("lastTestErrorMessage")

            if latency <= 0:
                quality = "timeout"
            elif not error_msg and latency < 200:
                quality = "excellent"  # 优秀
            elif not error_msg or latency < 300:
                quality = "good"       # 良好
            else:
                quality = "pass"       # 及格
            counts[quality] += 1

            node_list.append({
                "name": n.get("name", ""),
                "type": n.get("typeDescription", ""),
                "latency": latency,
                "quality": quality,
                "error": error_msg,
            })

        _Q_ORDER = {"excellent": 0, "good": 1, "pass": 2, "timeout": 3}
        node_list.sort(key=lambda x: (
            _Q_ORDER.get(x["quality"], 9),
            x["latency"] if x["latency"] > 0 else 99999,
        ))

        alive = counts["excellent"] + counts["good"] + counts["pass"]
        result[name] = {
            "total": total,
            "alive": alive,
            "timeout": counts["timeout"],
            "excellent": counts["excellent"],
            "good": counts["good"],
            "pass": counts["pass"],
            "nodes": node_list,
        }

    return jsonify(result)


# ── Entry IP analysis ─────────────────────────────────────────

_entry_cache = {}
_entry_cache_ts = 0
_ENTRY_CACHE_TTL = 3600  # 1 hour


def _parse_entry_hosts(node_text):
    """Extract unique server hostnames/IPs from Surge proxy-list text."""
    hosts = set()
    for line in node_text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        # Format: "Name = proto, server, port, ..."
        after_eq = line.split("=", 1)[1].strip()
        parts = [p.strip() for p in after_eq.split(",")]
        if len(parts) >= 2:
            hosts.add(parts[1])
    return sorted(hosts)


def _resolve_via_doh(hostname):
    """Resolve hostname via DNS-over-HTTPS (Google) to bypass Surge fake-ip."""
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": hostname, "type": "A"},
            timeout=5,
        )
        answers = r.json().get("Answer", [])
        ips = [a["data"] for a in answers if a.get("type") == 1]
        return ips[-1] if ips else None
    except Exception:
        return None


@bp.route("/api/airports/entry-ip")
def airport_entry_ip():
    """Resolve entry IPs for each airport and return geolocation + relay/direct tag."""
    global _entry_cache, _entry_cache_ts
    if time.time() - _entry_cache_ts < _ENTRY_CACHE_TTL and _entry_cache:
        return jsonify(_entry_cache)

    airports = _load_airports()
    if not airports:
        return jsonify({})

    # Collect all unique hosts across airports
    airport_hosts = {}
    all_hosts = set()
    for name in airports:
        fpath = SUB_STORE / f"{name}_surge.txt"
        if not fpath.exists():
            continue
        hosts = _parse_entry_hosts(fpath.read_text("utf-8"))
        airport_hosts[name] = hosts
        all_hosts.update(hosts)

    # Resolve all unique hosts via DoH
    host_to_ip = {}
    for h in all_hosts:
        # Check if already an IP
        try:
            import ipaddress as _ipa
            _ipa.ip_address(h)
            host_to_ip[h] = h
        except ValueError:
            ip = _resolve_via_doh(h)
            if ip:
                host_to_ip[h] = ip

    # Batch query ip-api.com for geolocation (max 100 per batch)
    unique_ips = list(set(host_to_ip.values()))
    ip_geo = {}
    for i in range(0, len(unique_ips), 100):
        batch = unique_ips[i:i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=query,country,regionName,isp,org",
                json=[{"query": ip} for ip in batch],
                timeout=10,
            )
            for item in r.json():
                ip_geo[item["query"]] = item
        except Exception as e:
            log.warning("ip-api.com batch failed: %s", e)

    # Build per-airport result
    result = {}
    for name, hosts in airport_hosts.items():
        entries = []
        seen_ips = set()
        for h in hosts:
            ip = host_to_ip.get(h)
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            geo = ip_geo.get(ip, {})
            country = geo.get("country", "")
            is_cn = country == "China"
            entries.append({
                "host": h,
                "ip": ip,
                "region": geo.get("regionName", ""),
                "isp": geo.get("isp", ""),
                "country": country,
            })

        # Determine relay vs direct: if ANY entry IP is in China → relay
        has_cn = any(e["country"] == "China" for e in entries)
        result[name] = {
            "type": "relay" if has_cn else "direct",
            "entries": entries,
        }

    _entry_cache = result
    _entry_cache_ts = time.time()
    return jsonify(result)
