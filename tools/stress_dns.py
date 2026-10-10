#!/usr/bin/env python3
"""Bounded, dependency-free UDP stress test for a running ESP32-C6-AdBlock."""

import argparse
import asyncio
import ipaddress
import json
import math
import secrets
import socket
import struct
import time
import urllib.request
from collections import Counter


def make_query(txid, domain):
    labels = domain.encode("ascii").split(b".")
    qname = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def skip_name(packet, pos):
    while pos < len(packet):
        length = packet[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2 if pos + 1 < len(packet) else None
        if length & 0xC0 or pos + 1 + length > len(packet):
            return None
        pos += 1 + length
    return None


def parse_reply(packet):
    if len(packet) < 12:
        return None
    flags = struct.unpack_from("!H", packet, 2)[0]
    qdcount, ancount = struct.unpack_from("!HH", packet, 4)
    pos = 12
    for _ in range(qdcount):
        pos = skip_name(packet, pos)
        if pos is None or pos + 4 > len(packet):
            return None
        pos += 4

    addresses = []
    for _ in range(ancount):
        pos = skip_name(packet, pos)
        if pos is None or pos + 10 > len(packet):
            return None
        record_type = struct.unpack_from("!H", packet, pos)[0]
        rdlength = struct.unpack_from("!H", packet, pos + 8)[0]
        pos += 10
        if pos + rdlength > len(packet):
            return None
        if record_type == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(packet[pos:pos + 4]))
        pos += rdlength

    return {
        "is_response": bool(flags & 0x8000),
        "rcode": flags & 0x000F,
        "addresses": addresses,
    }


def query_case(profile, index):
    if profile == "blocked":
        return f"load-{index:05d}.doubleclick.net", True
    if profile == "forward":
        return f"load-{index:05d}.example.com", False
    if index % 5 == 0:
        return f"load-{index:05d}.example.com", False
    return f"load-{index:05d}.doubleclick.net", True


def read_stats(host):
    try:
        with urllib.request.urlopen(f"http://{host}/stats.json", timeout=3) as response:
            payload = json.load(response)
        fields = (
            "domains", "heap", "blocked", "allowed", "dns_rx_drops",
            "upstream_rx_drops", "rssi", "uptime",
        )
        return {field: payload.get(field) for field in fields}
    except Exception as error:
        return {"unavailable": str(error)}


def percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[math.ceil(percent * len(ordered)) - 1], 3)


async def run_test(args, target_ip):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.setblocking(False)

    request_id_base = secrets.randbelow(65536)
    pending = {}
    latencies_ms = []
    rcode_counts = Counter()
    blocked_hits = 0
    blocked_mismatches = 0
    unexpected_sinkholes = 0
    invalid_replies = 0
    unmatched_replies = 0
    timeouts = 0
    sent = 0
    started = time.monotonic()

    async def fill_window():
        nonlocal sent
        while sent < args.requests and len(pending) < args.concurrency:
            index = sent
            txid = (request_id_base + index) & 0xFFFF
            domain, expected_blocked = query_case(args.profile, index)
            payload = make_query(txid, domain)
            await loop.sock_sendto(sock, payload, (target_ip, 53))
            pending[txid] = (time.monotonic(), expected_blocked)
            sent += 1

    try:
        await fill_window()
        while pending or sent < args.requests:
            now = time.monotonic()
            nearest_deadline = min(sent_at + args.timeout for sent_at, _ in pending.values())
            wait_seconds = max(0.001, nearest_deadline - now)
            try:
                packet, peer = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), wait_seconds)
            except asyncio.TimeoutError:
                now = time.monotonic()
                expired = [txid for txid, (sent_at, _) in pending.items()
                           if now - sent_at >= args.timeout]
                for txid in expired:
                    pending.pop(txid, None)
                    timeouts += 1
                await fill_window()
                continue

            if peer[0] != target_ip or len(packet) < 2:
                unmatched_replies += 1
                continue
            txid = struct.unpack_from("!H", packet)[0]
            request = pending.pop(txid, None)
            if request is None:
                unmatched_replies += 1
                continue

            sent_at, expected_blocked = request
            reply = parse_reply(packet)
            if reply is None or not reply["is_response"]:
                invalid_replies += 1
            else:
                latencies_ms.append((time.monotonic() - sent_at) * 1000)
                rcode_counts[str(reply["rcode"])] += 1
                is_sinkhole = "0.0.0.0" in reply["addresses"]
                if expected_blocked:
                    if reply["rcode"] == 0 and is_sinkhole:
                        blocked_hits += 1
                    else:
                        blocked_mismatches += 1
                elif is_sinkhole:
                    unexpected_sinkholes += 1
                if not expected_blocked and reply["rcode"] not in (0, 3):
                    invalid_replies += 1

            await fill_window()
    finally:
        sock.close()

    duration = time.monotonic() - started
    expected_blocked_total = sum(
        1 for index in range(args.requests) if query_case(args.profile, index)[1]
    )
    failures = timeouts + invalid_replies + blocked_mismatches + unexpected_sinkholes
    return {
        "target": args.host,
        "target_ip": target_ip,
        "profile": args.profile,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "sent": sent,
        "responses": len(latencies_ms),
        "timeouts": timeouts,
        "invalid_replies": invalid_replies,
        "unmatched_replies": unmatched_replies,
        "duration_seconds": round(duration, 3),
        "throughput_responses_per_second": round(len(latencies_ms) / duration, 1),
        "latency_ms": {
            "p50": percentile(latencies_ms, 0.50),
            "p95": percentile(latencies_ms, 0.95),
            "p99": percentile(latencies_ms, 0.99),
            "max": round(max(latencies_ms), 3) if latencies_ms else None,
        },
        "rcode_counts": dict(sorted(rcode_counts.items())),
        "blocked_queries_expected": expected_blocked_total,
        "blocked_answers_0_0_0_0": blocked_hits,
        "blocked_answer_mismatches": blocked_mismatches,
        "unexpected_sinkhole_answers": unexpected_sinkholes,
        "result": "PASS" if failures == 0 and len(latencies_ms) == args.requests else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="ESP32-C6 IP or resolvable hostname")
    parser.add_argument("--profile", choices=("blocked", "forward", "mixed"), default="mixed")
    parser.add_argument("--requests", type=int, default=1000, help="1 to 60000 DNS requests")
    parser.add_argument("--concurrency", type=int, default=64, help="1 to 128 outstanding requests")
    parser.add_argument("--timeout", type=float, default=2.0, help="per-request timeout in seconds")
    args = parser.parse_args()

    if not 1 <= args.requests <= 60000:
        parser.error("--requests must be between 1 and 60000")
    if not 1 <= args.concurrency <= 128:
        parser.error("--concurrency must be between 1 and 128")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        target_ip = socket.gethostbyname(args.host)
        ipaddress.IPv4Address(target_ip)
    except (OSError, ipaddress.AddressValueError) as error:
        parser.error(f"cannot resolve an IPv4 address for {args.host}: {error}")

    before = read_stats(args.host)
    result = asyncio.run(run_test(args, target_ip))
    after = read_stats(args.host)
    result["device_stats_before"] = before
    result["device_stats_after"] = after
    if "unavailable" not in before and "unavailable" not in after:
        result["device_counter_deltas"] = {
            key: after[key] - before[key]
            for key in ("blocked", "allowed", "dns_rx_drops", "upstream_rx_drops")
            if isinstance(before.get(key), int) and isinstance(after.get(key), int)
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["result"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
