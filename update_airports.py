#!/usr/bin/env python3
"""
Cron script: refresh all airports with auto_update=True.
Runs inside the surge-monitor container.

Includes proxy-download fallback for providers that block subconverter headers.
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote as urlquote

import requests

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("update_airports")

SUB_STORE = Path(config.SUB_STORE_PATH)
AIRPORTS_JSON = SUB_STORE / "airports.json"
SUBCONVERTER = config.SUBCONVERTER_URL

# Docker bridge gateway — subconverter (bridge) reaches surge-monitor (host) here
_LOCAL_SUB_BASE = "http://172.17.0.1:8866/sub"


def _build_subconv_url(raw_url):
    encoded = urlquote(raw_url, safe="")
    return (
        f"{SUBCONVERTER}/sub?target=surge&ver=4"
        f"&url={encoded}"
        "&insert=false"
        "&config=https%3A%2F%2Fraw.githubusercontent.com"
        "%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online.ini"
        "&append_type=false&emoji=true&list=true&tfo=false"
        "&scv=true&fdn=false&expand=true&sort=true&udp=true"
    )


def _fetch_nodes(subconv_url):
    resp = requests.get(subconv_url, timeout=30)
    resp.raise_for_status()
    text = resp.text
    text = text.replace(" = hysteria, ", " = hysteria2, ")
    text = re.sub(r",skip-cert-verify", ", skip-cert-verify", text)
    text = re.sub(r",sni=", ", sni=", text)
    lines = [l for l in text.splitlines() if l.strip() and " = " in l]
    return "\n".join(lines) + "\n"


def _fetch_nodes_via_proxy(raw_url):
    """Pre-download subscription ourselves (clean headers), then convert via subconverter."""
    resp = requests.get(raw_url, timeout=30,
                        headers={"User-Agent": "clash-verge/v2.2.3"})
    resp.raise_for_status()
    temp_path = SUB_STORE / "_temp_raw.txt"
    temp_path.write_text(resp.text, "utf-8")
    local_url = f"{_LOCAL_SUB_BASE}/_temp_raw.txt"
    return _fetch_nodes(_build_subconv_url(local_url))


def main():
    if not AIRPORTS_JSON.exists():
        log.info("No airports.json, skip")
        return

    airports = json.loads(AIRPORTS_JSON.read_text("utf-8"))

    for name, info in airports.items():
        if not info.get("auto_update", False):
            log.info("%s: skip (auto_update=false)", name)
            continue

        url = info.get("subconverter_url", "")
        raw_url = info.get("subscribe_url", "")
        if not url and not raw_url:
            log.info("%s: skip (no url)", name)
            continue
        if not url:
            url = _build_subconv_url(raw_url)

        try:
            node_text = _fetch_nodes(url)
        except Exception:
            if raw_url:
                log.info("%s: direct fetch failed, retrying via proxy download", name)
                try:
                    node_text = _fetch_nodes_via_proxy(raw_url)
                except Exception as e:
                    log.warning("%s: proxy fallback also failed - %s", name, e)
                    continue
            else:
                log.warning("%s: fetch failed and no raw subscribe_url for fallback", name)
                continue

        node_count = len([l for l in node_text.splitlines() if l.strip()])
        if node_count > 0:
            fpath = SUB_STORE / f"{name}_surge.txt"
            fpath.write_text(node_text, "utf-8")
            os.chmod(str(fpath), 0o644)
            log.info("%s: updated, %d nodes", name, node_count)
        else:
            log.info("%s: 0 nodes, keeping old file", name)


if __name__ == "__main__":
    main()
