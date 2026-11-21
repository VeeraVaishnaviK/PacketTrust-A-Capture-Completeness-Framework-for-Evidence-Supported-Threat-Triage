"""
triage.py – Detect network threats from a PCAP.

Detectors
---------
1. Port Scan       – One source SYNs >= 15 distinct dst ports on same host
2. SYN Flood       – >= 100 SYNs to same dst ip:port within 5 s, mostly unanswered
3. ARP Spoofing    – Different MAC addresses claim the same IP
4. SSH Brute Force – >= 10 TCP connections to port 22 from same source in 60 s

Each finding includes:
  attack, severity, status, detail, supporting_packets, confidence
Status values:
  Confirmed    – strong statistical evidence from captured packets
  Probable     – pattern detected but partial evidence
  Unverifiable – too few supporting packets to draw conclusions
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.all import rdpcap, TCP, IP, ARP as ARP_Layer


# ---------------------------------------------------------------------------
# individual detectors
# ---------------------------------------------------------------------------

def _detect_port_scan(packets) -> list[dict]:
    """Detect horizontal port scans."""
    syn_map: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"ports": set(), "idxs": []})
    )

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = str(pkt[TCP].flags)
            if "S" in flags and "A" not in flags:
                src = pkt[IP].src
                dst = pkt[IP].dst
                syn_map[src][dst]["ports"].add(pkt[TCP].dport)
                syn_map[src][dst]["idxs"].append(idx)

    findings = []
    for src, targets in syn_map.items():
        for dst, info in targets.items():
            n_ports = len(info["ports"])
            if n_ports >= 15:
                conf = min(1.0, n_ports / 100)
                if n_ports >= 50:
                    status = "Confirmed"
                elif n_ports >= 15:
                    status = "Probable"
                else:
                    status = "Unverifiable"
                findings.append({
                    "attack": "Port Scan",
                    "severity": "Medium",
                    "status": status,
                    "detail": f"Host {src} scanned {n_ports} ports on {dst}",
                    "supporting_packets": info["idxs"][:50],
                    "confidence": round(conf, 2),
                })
    return findings


def _detect_syn_flood(packets) -> list[dict]:
    """Detect SYN flood attacks."""
    syn_targets: dict[str, list] = defaultdict(list)
    ack_set: set[str] = set()

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = str(pkt[TCP].flags)
            dst_key = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            if "S" in flags and "A" not in flags:
                syn_targets[dst_key].append((float(pkt.time), idx))
            if "S" in flags and "A" in flags:
                ack_set.add(f"{pkt[IP].src}:{pkt[TCP].sport}")

    findings = []
    for target, syns in syn_targets.items():
        if len(syns) < 100:
            continue
        syns.sort()
        i = 0
        for j in range(len(syns)):
            while syns[j][0] - syns[i][0] > 5.0:
                i += 1
            window_count = j - i + 1
            if window_count >= 100:
                answered = sum(1 for _, idx in syns[i:j + 1] if target in ack_set)
                ratio = answered / window_count
                if ratio < 0.3:
                    conf = min(1.0, window_count / 500)
                    findings.append({
                        "attack": "SYN Flood",
                        "severity": "High",
                        "status": "Confirmed" if window_count >= 500 else "Probable",
                        "detail": (
                            f"{window_count} SYN packets to {target} in "
                            f"{round(syns[j][0] - syns[i][0], 1)}s, "
                            f"{int(ratio * 100)}% answered"
                        ),
                        "supporting_packets": [idx for _, idx in syns[i:j + 1]][:50],
                        "confidence": round(conf, 2),
                    })
                    break
    return findings


def _detect_arp_spoof(packets) -> list[dict]:
    """Detect ARP spoofing (IP claimed by multiple MACs)."""
    ip_to_macs: dict[str, dict] = defaultdict(
        lambda: {"macs": set(), "idxs": []}
    )

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(ARP_Layer):
            arp = pkt[ARP_Layer]
            if arp.op == 2:  # ARP reply
                ip_to_macs[arp.psrc]["macs"].add(arp.hwsrc)
                ip_to_macs[arp.psrc]["idxs"].append(idx)

    findings = []
    for ip_addr, info in ip_to_macs.items():
        if len(info["macs"]) > 1:
            findings.append({
                "attack": "ARP Spoofing",
                "severity": "High",
                "status": "Confirmed",
                "detail": (
                    f"IP {ip_addr} claimed by {len(info['macs'])} MACs: "
                    f"{', '.join(info['macs'])}"
                ),
                "supporting_packets": info["idxs"][:50],
                "confidence": 0.95,
            })
    return findings


def _detect_ssh_brute(packets) -> list[dict]:
    """Detect SSH brute force attempts."""
    ssh_conns: dict[str, list] = defaultdict(list)

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].dport == 22 and "S" in str(pkt[TCP].flags) and "A" not in str(pkt[TCP].flags):
                ssh_conns[pkt[IP].src].append((float(pkt.time), idx))

    findings = []
    for src, conns in ssh_conns.items():
        if len(conns) < 10:
            continue
        conns.sort()
        i = 0
        for j in range(len(conns)):
            while conns[j][0] - conns[i][0] > 60.0:
                i += 1
            window = j - i + 1
            if window >= 10:
                conf = min(1.0, window / 50)
                findings.append({
                    "attack": "SSH Brute Force",
                    "severity": "High",
                    "status": "Confirmed" if window >= 30 else "Probable",
                    "detail": (
                        f"{window} SSH SYNs from {src} in "
                        f"{round(conns[j][0] - conns[i][0], 1)}s"
                    ),
                    "supporting_packets": [idx for _, idx in conns[i:j + 1]][:50],
                    "confidence": round(conf, 2),
                })
                break
    return findings


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    _detect_port_scan,
    _detect_syn_flood,
    _detect_arp_spoof,
    _detect_ssh_brute,
]


def analyse(pcap_path: str) -> dict[str, Any]:
    """Run all threat detectors against a PCAP file."""
    packets = list(rdpcap(pcap_path))
    return analyse_packets(packets, pcap_path.replace("\\", "/").split("/")[-1])


def analyse_packets(packets: list, filename: str = "unknown") -> dict[str, Any]:
    """Run all threat detectors against an already-loaded packet list."""
    findings: list[dict] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(packets))

    sev_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))

    return {
        "file": filename,
        "findings": findings,
    }
