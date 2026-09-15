#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

def human_time(ts, now=None):
    if not ts:
        return "never"
    base = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if now is not None:
        base += f" ({ago(ts, now)})"
    return base


def ago(ts, now):
    if not ts:
        return ""
    secs = int(now - ts)
    if secs < 0:
        return "in future"
    units = (("d", 86400), ("h", 3600), ("m", 60), ("s", 1))
    parts = []
    for name, size in units:
        if secs >= size:
            parts.append(f"{secs // size}{name}")
            secs %= size
    return " ".join(parts[:2]) + " ago"


def fmt_bytes(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="peers.json URL")
    ap.add_argument("-u", "--user", required=True, help="basic auth username")
    ap.add_argument("-p", "--password", default=os.environ.get("API_PASS"), help="basic auth password (or API_PASS env var)")
    ap.add_argument(
        "-s", "--sort",
        default="last_handshake",
        choices=["id", "last_handshake", "created", "ip", "rx", "tx"],
        help="column to sort by (default: last_handshake)",
    )
    ap.add_argument("--desc", action="store_true", help="sort descending")
    args = ap.parse_args()

    if not args.password:
        ap.error("password is required (via --password or API_PASS env var)")

    token = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    req = urllib.request.Request(
        args.url,
        headers={
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)

    peers = [
        {
            "id": pid,
            **meta,
        }
        for pid, meta in data.items()
    ]
    field = {"rx": "rx_bytes", "tx": "tx_bytes"}.get(args.sort, args.sort)
    peers.sort(key=lambda p: p[field], reverse=args.desc)

    headers = ["ID", "Last Handshake", "Created", "IP", "Rx", "Tx"]
    now = datetime.now(timezone.utc).timestamp()
    rows = [
        [
            p["id"],
            human_time(p["last_handshake"], now),
            human_time(p["created"], now),
            p["ip"],
            fmt_bytes(p["rx_bytes"]),
            fmt_bytes(p["tx_bytes"]),
        ]
        for p in peers
    ]

    widths = [max(len(headers[i]), *(len(r[i]) for r in rows)) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*r))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
