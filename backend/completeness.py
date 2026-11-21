"""
completeness.py – Parse a PCAP and compute a capture-completeness score.

Gaps detected:
  • TCP sequence gaps      – missing segments within a flow (packet drop in transit)
  • IP ID gaps             – non-sequential IP identification values from a host
  • Timestamp jumps        – gaps (> 3 s) between packets (capture buffer overflow)
  • Missing TCP handshakes – data flow without observed SYN/SYN-ACK
  • Missing teardowns      – connections terminated without FIN/RST
  • Retransmissions        – duplicate sequence numbers (network congestion/loss)

Score formula (per flow):
  score = max(0, 100 − penalties)
    −8  per TCP seq gap
    −3  per IP ID gap
    −5  per timestamp jump
    −12 if handshake is missing
    −5  if teardown is missing (no FIN/RST seen)
    −2  per retransmission

Overall score = weighted average of flow scores penalized by capture-level anomalies.
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
    if src > dst:
        src, dst = dst, src
    return f"{src}<->{dst} TCP"


def _detect_tcp_seq_gaps(pkts) -> int:
    """Count gaps in TCP sequence numbers within sorted packets."""
    gaps = 0
    dirs: dict[str, list] = defaultdict(list)
    for p in pkts:
        d = f"{p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}"
        dirs[d].append(p)

    for direction_pkts in dirs.values():
        sorted_p = sorted(direction_pkts, key=lambda x: x[TCP].seq)
        for i in range(1, len(sorted_p)):
            prev = sorted_p[i - 1]
            curr = sorted_p[i]
            payload_len = len(bytes(prev[TCP].payload))
            if payload_len == 0:
                payload_len = 1  # SYN/FIN consume 1 seq number
            expected_next = prev[TCP].seq + payload_len
            if curr[TCP].seq > expected_next + 10:
                gaps += 1
    return gaps


def _detect_ip_id_gaps(pkts) -> int:
    """Count non-sequential IP ID jumps for each source IP (sorted chronologically)."""
    gaps = 0
    dirs: dict[str, list] = defaultdict(list)
    for p in pkts:
        if p.haslayer(IP) and p[IP].id != 0:
            dirs[p[IP].src].append(p)
    for dir_pkts in dirs.values():
        sorted_p = sorted(dir_pkts, key=lambda x: float(x.time))
        for i in range(1, len(sorted_p)):
            diff = sorted_p[i][IP].id - sorted_p[i - 1][IP].id
            if 1 < diff < 500:
                gaps += 1
    return gaps


def _detect_timestamp_jumps(pkts, threshold: float = 3.0) -> int:
    """Count gaps where consecutive timestamps differ > threshold."""
    jumps = 0
    times = sorted(float(p.time) for p in pkts)
    for i in range(1, len(times)):
        if times[i] - times[i - 1] > threshold:
            jumps += 1
    return jumps


def _missing_handshake(pkts) -> bool:
    """Return True if the flow has data but no SYN was captured."""
    has_syn = False
    has_payload = False
    for p in pkts:
        f = str(p[TCP].flags)
        if "S" in f and "A" not in f:
            has_syn = True
        if len(bytes(p[TCP].payload)) > 0:
            has_payload = True
    return has_payload and not has_syn


def _missing_teardown(pkts) -> bool:
    """Return True if the flow has no FIN or RST."""
    for p in pkts:
        f = str(p[TCP].flags)
        if "F" in f or "R" in f:
            return False
    return len(pkts) > 2


def _count_retransmissions(pkts) -> int:
    """Count likely retransmissions (duplicate seq in same direction)."""
    retrans = 0
    dirs: dict[str, set] = defaultdict(set)
    for p in pkts:
        d = f"{p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}"
        seq = p[TCP].seq
        if seq in dirs[d]:
            retrans += 1
        dirs[d].add(seq)
    return retrans


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def analyse(pcap_path: str) -> dict[str, Any]:
    """
    Analyse a PCAP file and return capture completeness metrics.
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

    # Capture-level gap detections
    capture_ip_id_gaps = _detect_ip_id_gaps(packets)
    capture_ts_jumps = _detect_timestamp_jumps(packets, threshold=3.0)

    total_tcp_seq_gaps = 0
    total_missing_hs = 0
    total_missing_td = 0
    total_retrans = 0

    flow_results: list[dict] = []

    for fid, fpkts in flows.items():
        seq_gaps = _detect_tcp_seq_gaps(fpkts)
        flow_id_gaps = _detect_ip_id_gaps(fpkts)
        flow_ts_jumps = _detect_timestamp_jumps(fpkts, threshold=5.0)
        miss_hs = _missing_handshake(fpkts)
        miss_td = _missing_teardown(fpkts)
        retrans = _count_retransmissions(fpkts)

        total_tcp_seq_gaps += seq_gaps
        total_missing_hs += int(miss_hs)
        total_missing_td += int(miss_td)
        total_retrans += retrans

        penalty = (
            seq_gaps * 8
            + flow_id_gaps * 4
            + flow_ts_jumps * 6
            + (12 if miss_hs else 0)
            + (5 if miss_td else 0)
            + retrans * 2
        )
        score = max(0.0, 100.0 - penalty)

        issues: list[str] = []
        if seq_gaps:
            issues.append(f"{seq_gaps} TCP seq gap(s)")
        if flow_id_gaps:
            issues.append(f"{flow_id_gaps} IP ID gap(s)")
        if flow_ts_jumps:
            issues.append(f"{flow_ts_jumps} timestamp jump(s)")
        if miss_hs:
            issues.append("missing handshake")
        if miss_td:
            issues.append("no teardown (FIN/RST)")
        if retrans:
            issues.append(f"{retrans} retransmission(s)")

        flow_results.append({
            "flow_id": fid,
            "packets": len(fpkts),
            "score": round(score, 1),
            "issues": issues,
        })

    # overall weighted score, penalized by capture-level global gaps
    total_pkts = sum(f["packets"] for f in flow_results) or 1
    raw_score = sum(f["score"] * f["packets"] for f in flow_results) / total_pkts
    global_penalty = min(20.0, (capture_ip_id_gaps * 0.5) + (capture_ts_jumps * 2.0))
    overall = max(0.0, min(100.0, round(raw_score - global_penalty, 1)))

    # Sort flows: lowest score first (problematic flows first)
    sorted_flows = sorted(flow_results, key=lambda f: (f["score"], -f["packets"]))

    return {
        "file": pcap_path.replace("\\", "/").split("/")[-1],
        "overall_score": overall,
        "packet_count": len(packets),
        "duration_sec": duration,
        "gaps": {
            "tcp_seq_gaps": total_tcp_seq_gaps,
            "ip_id_gaps": capture_ip_id_gaps,
            "timestamp_jumps": capture_ts_jumps,
            "missing_handshakes": total_missing_hs,
            "missing_teardowns": total_missing_td,
            "retransmissions": total_retrans,
        },
        "flows": sorted_flows,
    }
