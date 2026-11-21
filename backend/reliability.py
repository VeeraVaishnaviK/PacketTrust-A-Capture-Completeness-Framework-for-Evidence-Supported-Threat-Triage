"""
reliability.py – Run triage at multiple loss levels across many trials
and compare with ground truth to measure detection reliability.

Optimised: reads the source PCAP once and simulates loss in-memory.
"""

from __future__ import annotations

import os
import random
import statistics
from typing import Any

from scapy.all import rdpcap, wrpcap

import triage


def _reliability_label(detection_rate: float) -> str:
    if detection_rate >= 0.9:
        return "High"
    if detection_rate >= 0.6:
        return "Medium"
    return "Low"


def _simulate_in_memory(packets: list, loss_pct: float, seed: int) -> list:
    """Drop packets in-memory (random mode) without writing to disk."""
    if loss_pct <= 0:
        return packets
    rng = random.Random(seed)
    return [p for p in packets if rng.random() > loss_pct / 100]


def run_experiment(
    pcap_path: str,
    loss_levels: list[int] | None = None,
    trials: int = 20,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """
    1. Run triage at 0% loss to establish ground truth.
    2. For each loss level, run *trials* rounds of in-memory loss + triage.
    3. Compare detected attacks with ground truth.
    """
    if loss_levels is None:
        loss_levels = [0, 10, 20, 30, 50]

    out_dir = output_dir or os.path.dirname(pcap_path)

    # Read the PCAP once
    all_packets = list(rdpcap(pcap_path))

    # --- ground truth (full capture, no loss) ---
    gt = triage.analyse_packets(all_packets, os.path.basename(pcap_path))
    ground_truth_attacks = sorted({f["attack"] for f in gt["findings"]})

    results: list[dict] = []

    for loss_pct in loss_levels:
        trial_detections: list[float] = []
        trial_fn: list[float] = []
        trial_conf: list[float] = []

        for t in range(trials):
            if loss_pct == 0:
                trial_result = gt
            else:
                degraded = _simulate_in_memory(all_packets, loss_pct, seed=t)
                if not degraded:
                    trial_result = {"findings": []}
                else:
                    trial_result = triage.analyse_packets(
                        degraded, os.path.basename(pcap_path)
                    )

            detected = {f["attack"] for f in trial_result["findings"]}
            confs = [f["confidence"] for f in trial_result["findings"]] or [0.0]

            if ground_truth_attacks:
                det_rate = len(detected & set(ground_truth_attacks)) / len(ground_truth_attacks)
                fn_rate = 1.0 - det_rate
            else:
                det_rate = 1.0
                fn_rate = 0.0

            trial_detections.append(det_rate)
            trial_fn.append(fn_rate)
            trial_conf.append(statistics.mean(confs))

        avg_det = statistics.mean(trial_detections)
        avg_fn = statistics.mean(trial_fn)
        avg_conf = statistics.mean(trial_conf)

        results.append({
            "loss_pct": loss_pct,
            "detection_rate": round(avg_det, 3),
            "false_negative_rate": round(avg_fn, 3),
            "avg_confidence": round(avg_conf, 3),
            "reliability": _reliability_label(avg_det),
        })

    return {
        "file": os.path.basename(pcap_path),
        "ground_truth": ground_truth_attacks,
        "results": results,
    }
