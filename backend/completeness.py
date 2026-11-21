"""
completeness.py – Parse a PCAP and compute a capture-completeness score.

Gaps detected:
  • TCP sequence gaps (missing segments within a flow)
  • IP ID gaps (non-sequential IP identification values)
  • Timestamp jumps (> 5 s gap between consecutive packets)
  • Missing TCP handshakes (data flow without observed SYN/SYN-ACK)

Score formula (per flow):
  score = max(0, 100 − penalties)
    − 10 per TCP seq gap
    − 5  per IP ID gap
    − 5  per timestamp jump
    − 15 if handshake is missing

Overall score = weighted average of flow scores (weight = packet count).
"""

from __future__ import annotations
from collections import defaultdict
from typing import Any

from scapy.all import rdpcap, TCP, IP, ARP


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _flow_key(pkt) -> str | None:
    """Return a canonical 5-tuple string for TCP/IP packets."""
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None
    ip = pkt[IP]
    tcp = pkt[TCP]
    src = f"{ip.src}:{tcp.sport}"
    dst = f"{ip.dst}:{tcp.dport}"
    # canonical ordering so both directions map to the same flow
    if src > dst:
        src, dst = dst, src
    return f"{src}<->{dst} TCP"


def _detect_tcp_seq_gaps(pkts) -> int:
    """Count gaps in TCP sequence numbers within a *sorted* packet list."""
    gaps = 0
    # group by direction
    dirs: dict[str, list] = defaultdict(list)
    for p in pkts:
        d = f"{p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}"
        dirs[d].append(p)

    for direction_pkts in dirs.values():
        sorted_p = sorted(direction_pkts, key=lambda x: x[TCP].seq)
        for i in range(1, len(sorted_p)):
            prev = sorted_p[i - 1]
            curr = sorted_p[i]
            expected_next = prev[TCP].seq + max(len(bytes(prev[TCP].payload)), 1)
            if curr[TCP].seq > expected_next + 1:
                gaps += 1
    return gaps


def _detect_ip_id_gaps(pkts) -> int:
    """Count non-sequential IP ID jumps (same src→dst direction)."""
    gaps = 0
    dirs: dict[str, list] = defaultdict(list)
    for p in pkts:
        dirs[p[IP].src].append(p)
    for dir_pkts in dirs.values():
        sorted_p = sorted(dir_pkts, key=lambda x: x[IP].id)
        for i in range(1, len(sorted_p)):
            diff = sorted_p[i][IP].id - sorted_p[i - 1][IP].id
            if diff > 1:
                gaps += 1
    return gaps


def _detect_timestamp_jumps(pkts, threshold: float = 5.0) -> int:
    """Count gaps where consecutive packet timestamps differ > threshold."""
    jumps = 0
    times = sorted(float(p.time) for p in pkts)
    for i in range(1, len(times)):
        if times[i] - times[i - 1] > threshold:
            jumps += 1
    return jumps


def _missing_handshake(pkts) -> bool:
    """Return True if the flow has data but no SYN was captured."""
    flags = set()
    has_payload = False
    for p in pkts:
        f = p[TCP].flags
        flags.add(str(f))
        if len(bytes(p[TCP].payload)) > 0:
            has_payload = True
    return has_payload and "S" not in flags


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def analyse(pcap_path: str) -> dict[str, Any]:
    """
    Analyse a PCAP file and return completeness metrics.

    Returns dict matching the /api/completeness response format.
    """
    packets = rdpcap(pcap_path)

    # group by flow
    flows: dict[str, list] = defaultdict(list)
    non_tcp = 0
    for pkt in packets:
        key = _flow_key(pkt)
        if key:
            flows[key].append(pkt)
        else:
            non_tcp += 1

    duration = 0.0
    if len(packets) >= 2:
        times = [float(p.time) for p in packets]
        duration = round(max(times) - min(times), 2)

    total_tcp_seq_gaps = 0
    total_ip_id_gaps = 0
    total_ts_jumps = 0
    total_missing_hs = 0

    flow_results: list[dict] = []

    for fid, fpkts in flows.items():
        seq_gaps = _detect_tcp_seq_gaps(fpkts)
        id_gaps = _detect_ip_id_gaps(fpkts)
        ts_jumps = _detect_timestamp_jumps(fpkts)
        miss_hs = _missing_handshake(fpkts)

        total_tcp_seq_gaps += seq_gaps
        total_ip_id_gaps += id_gaps
        total_ts_jumps += ts_jumps
        total_missing_hs += int(miss_hs)

        penalty = seq_gaps * 10 + id_gaps * 5 + ts_jumps * 5 + (15 if miss_hs else 0)
        score = max(0.0, 100.0 - penalty)

        issues: list[str] = []
        if seq_gaps:
            issues.append(f"{seq_gaps} TCP seq gap(s)")
        if id_gaps:
            issues.append(f"{id_gaps} IP ID gap(s)")
        if ts_jumps:
            issues.append(f"{ts_jumps} timestamp jump(s)")
        if miss_hs:
            issues.append("missing handshake")

        flow_results.append({
            "flow_id": fid,
            "packets": len(fpkts),
            "score": round(score, 1),
            "issues": issues,
        })

    # overall weighted score
    total_pkts = sum(f["packets"] for f in flow_results) or 1
    overall = sum(f["score"] * f["packets"] for f in flow_results) / total_pkts

    return {
        "file": pcap_path.replace("\\", "/").split("/")[-1],
        "overall_score": round(overall, 1),
        "packet_count": len(packets),
        "duration_sec": duration,
        "gaps": {
            "tcp_seq_gaps": total_tcp_seq_gaps,
            "ip_id_gaps": total_ip_id_gaps,
            "timestamp_jumps": total_ts_jumps,
            "missing_handshakes": total_missing_hs,
        },
        "flows": sorted(flow_results, key=lambda f: f["score"]),
    }
