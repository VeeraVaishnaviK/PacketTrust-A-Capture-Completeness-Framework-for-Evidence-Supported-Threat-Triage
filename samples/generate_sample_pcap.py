"""
generate_sample_pcap.py – Create a synthetic PCAP with known attacks
for testing PacketTrust without a lab environment.

Generates: samples/sample_attack.pcap
Attacks embedded: Port Scan, SYN Flood, ARP Spoof, SSH Brute Force
"""

import os
import random
import sys

from scapy.all import (
    IP, TCP, Ether, ARP, wrpcap, RandShort,
)

OUTFILE = os.path.join(os.path.dirname(__file__), "sample_attack.pcap")

packets = []
base_time = 1700000000.0  # arbitrary epoch


def ts(offset):
    return base_time + offset


# ── 1. Normal background traffic ──────────────────────────────────────────
print("[*] Generating normal traffic …")
for i in range(200):
    sport = random.randint(49152, 65535)
    pkt = (
        IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=sport, dport=80, flags="S", seq=random.randint(1000, 99999))
    )
    pkt.time = ts(i * 0.05)
    packets.append(pkt)

    # SYN-ACK back
    sa = (
        IP(src="93.184.216.34", dst="192.168.1.10")
        / TCP(sport=80, dport=sport, flags="SA", seq=random.randint(1000, 99999), ack=pkt[TCP].seq + 1)
    )
    sa.time = ts(i * 0.05 + 0.01)
    packets.append(sa)


# ── 2. Port Scan (nmap-style SYN scan) ────────────────────────────────────
print("[*] Generating port scan …")
t = 15.0
for port in range(1, 201):  # 200 ports → well above 15-port threshold
    pkt = (
        IP(src="10.0.0.5", dst="192.168.1.100")
        / TCP(sport=random.randint(49152, 65535), dport=port, flags="S", seq=random.randint(1000, 99999))
    )
    pkt.time = ts(t)
    packets.append(pkt)
    t += 0.002


# ── 3. SYN Flood ─────────────────────────────────────────────────────────
print("[*] Generating SYN flood …")
t = 25.0
for i in range(600):  # 600 SYNs in ~3 s
    pkt = (
        IP(src=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", dst="192.168.1.100")
        / TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(1000, 999999))
    )
    pkt.time = ts(t)
    packets.append(pkt)
    t += 0.005


# ── 4. ARP Spoofing ──────────────────────────────────────────────────────
print("[*] Generating ARP spoof …")
t = 35.0
for i in range(20):
    # Legitimate ARP reply
    pkt1 = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.1", hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10")
    )
    pkt1.time = ts(t)
    packets.append(pkt1)

    # Spoofed ARP reply (different MAC for same IP)
    pkt2 = (
        Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc="de:ad:be:ef:00:01", psrc="192.168.1.1", hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10")
    )
    pkt2.time = ts(t + 0.5)
    packets.append(pkt2)
    t += 1.0


# ── 5. SSH Brute Force ───────────────────────────────────────────────────
print("[*] Generating SSH brute force …")
t = 50.0
for i in range(50):  # 50 connection attempts in ~25 s
    pkt = (
        IP(src="10.0.0.99", dst="192.168.1.100")
        / TCP(sport=random.randint(49152, 65535), dport=22, flags="S", seq=random.randint(1000, 99999))
    )
    pkt.time = ts(t)
    packets.append(pkt)
    t += 0.5


# ── Write out ─────────────────────────────────────────────────────────────
packets.sort(key=lambda p: float(p.time))
wrpcap(OUTFILE, packets)
print(f"\n[+] Wrote {len(packets)} packets to {OUTFILE}")
