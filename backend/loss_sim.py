"""
loss_sim.py – Simulate packet loss on a PCAP file.

Modes:
  • random  – drop each packet independently with probability = loss_pct/100
  • burst   – drop contiguous bursts (burst length ~ 5-15 packets)
"""

from __future__ import annotations

import os
import random
from typing import Literal

from scapy.all import rdpcap, wrpcap


def simulate(
    pcap_path: str,
    loss_pct: float,
    mode: Literal["random", "burst"] = "random",
    output_dir: str | None = None,
    seed: int | None = None,
) -> dict:
    """
    Drop packets from *pcap_path* at the requested loss percentage.

    Returns metadata about what was dropped and the path to the new file.
    """
    if seed is not None:
        random.seed(seed)

    packets = list(rdpcap(pcap_path))
    n = len(packets)

    if loss_pct <= 0:
        keep = list(range(n))
    elif mode == "random":
        keep = [i for i in range(n) if random.random() > loss_pct / 100]
    else:  # burst
        keep = list(range(n))
        to_drop = int(n * loss_pct / 100)
        dropped = 0
        while dropped < to_drop and keep:
            burst_len = random.randint(5, 15)
            start = random.randint(0, max(0, len(keep) - 1))
            end = min(start + burst_len, len(keep))
            del keep[start:end]
            dropped += end - start

    remaining = [packets[i] for i in keep]

    # write output
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    out_name = f"{base}_loss{int(loss_pct)}.pcap"
    out_dir = output_dir or os.path.dirname(pcap_path)
    out_path = os.path.join(out_dir, out_name)

    if remaining:
        wrpcap(out_path, remaining)
    else:
        # write an empty pcap (scapy needs at least 1 pkt, so handle edge)
        wrpcap(out_path, [])

    return {
        "original_packets": n,
        "remaining_packets": len(remaining),
        "dropped": n - len(remaining),
        "output_file": out_name,
    }
