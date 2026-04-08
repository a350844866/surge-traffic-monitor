#!/usr/bin/env python3
"""
Cron script: refresh all airports with auto_update=True.
Runs inside the surge-monitor container.
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote as urlquote

import requests

import config

SUB_STORE = Path(config.SUB_STORE_PATH)
AIRPORTS_JSON = SUB_STORE / "airports.json"


def fetch_nodes(subconv_url):
    resp = requests.get(subconv_url, timeout=30)
    resp.raise_for_status()
    text = resp.text
    text = text.replace(" = hysteria, ", " = hysteria2, ")
    text = re.sub(r",skip-cert-verify", ", skip-cert-verify", text)
    text = re.sub(r",sni=", ", sni=", text)
    lines = [l for l in text.splitlines() if l.strip() and " = " in l]
    return "\n".join(lines) + "\n"


def main():
    if not AIRPORTS_JSON.exists():
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No airports.json, skip")
        return

    airports = json.loads(AIRPORTS_JSON.read_text("utf-8"))

    for name, info in airports.items():
        if not info.get("auto_update", False):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}: skip (auto_update=false)")
            continue

        url = info.get("subconverter_url", "")
        if not url:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}: skip (no url)")
            continue

        try:
            node_text = fetch_nodes(url)
            node_count = len([l for l in node_text.splitlines() if l.strip()])
            if node_count > 0:
                fpath = SUB_STORE / f"{name}_surge.txt"
                fpath.write_text(node_text, "utf-8")
                os.chmod(str(fpath), 0o644)
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}: updated, {node_count} nodes")
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}: 0 nodes, keeping old file")
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}: failed - {e}")


if __name__ == "__main__":
    main()
