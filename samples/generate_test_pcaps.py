"""
generate_test_pcaps.py – Create realistic test PCAP files for PacketTrust.

Each scenario includes realistic network forensic characteristics:
  - Sequential IP IDs with occasional drops (IP ID gaps)
  - Missing SYN/SYN-ACK (capture started mid-session)
  - TCP sequence gaps (packet drops in transit)
  - Timestamp jumps (>3-5s gaps simulating capture buffer drops)
  - Retransmissions (duplicate sequence numbers)
  - Missing teardowns (FIN/RST truncated)

Generates 5 distinct scenarios:
  1. sample_port_scan.pcap       – Port scan + background traffic
  2. sample_syn_flood.pcap       – SYN flood attack
  3. sample_arp_spoof.pcap       – ARP spoofing attack
  4. sample_ssh_brute.pcap       – SSH brute force attempts
  5. sample_mixed_attacks.pcap   – All 4 attacks combined

Writes to both samples/ and backend/uploads/ for immediate testing.
"""

import os
import random
import shutil

from scapy.all import IP, TCP, UDP, Ether, ARP, ICMP, DNS, DNSQR, Raw, wrpcap

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend", "uploads")
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

random.seed(42)
BASE_TIME = 1700000000.0


def ts(offset):
    return BASE_TIME + offset


# Host IP ID trackers for realistic sequential IP identification
_host_ipid = {}

def next_ipid(host: str, force_gap: bool = False) -> int:
    global _host_ipid
    if host not in _host_ipid:
        _host_ipid[host] = random.randint(1000, 20000)
    if force_gap:
        _host_ipid[host] += random.randint(3, 8)  # simulate missed packets
    else:
        _host_ipid[host] += 1
    return _host_ipid[host] & 0xFFFF


# ---------------------------------------------------------------------------
# Realistic traffic generators with imperfections
# ---------------------------------------------------------------------------

def realistic_http_flows(start_t, count=50, use_ether=False, missing_hs_pct=0.15, gap_pct=0.12):
    pkts = []
    t = start_t
    client_mac = "aa:bb:cc:dd:ee:10"
    gw_mac = "aa:bb:cc:dd:ee:01"

    for i in range(count):
        sport = random.randint(49152, 65535)
        client = f"192.168.1.{random.randint(10, 50)}"
        server = random.choice(["93.184.216.34", "142.250.80.46", "151.101.1.69", "104.21.32.1"])
        skip_handshake = random.random() < missing_hs_pct
        has_seq_gap = random.random() < gap_pct
        has_id_gap = random.random() < 0.15
        data_exchanges = random.randint(2, 6)

        def wrap(ip_pkt):
            if use_ether:
                s = ip_pkt[IP].src
                if s.startswith("192.168"):
                    return Ether(src=client_mac, dst=gw_mac) / ip_pkt
                else:
                    return Ether(src=gw_mac, dst=client_mac) / ip_pkt
            return ip_pkt

        seq_c = random.randint(100000, 999999)
        seq_s = random.randint(100000, 999999)

        if not skip_handshake:
            # SYN
            syn = wrap(IP(src=client, dst=server, id=next_ipid(client)) / TCP(sport=sport, dport=80, flags="S", seq=seq_c))
            syn.time = ts(t)
            pkts.append(syn)
            t += 0.015

            # SYN-ACK
            sa = wrap(IP(src=server, dst=client, id=next_ipid(server)) / TCP(sport=80, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1))
            sa.time = ts(t)
            pkts.append(sa)
            seq_c += 1
            seq_s += 1
            t += 0.012

            # ACK
            ack = wrap(IP(src=client, dst=server, id=next_ipid(client)) / TCP(sport=sport, dport=80, flags="A", seq=seq_c, ack=seq_s))
            ack.time = ts(t)
            pkts.append(ack)
            t += 0.005
        else:
            # Mid-stream: no handshake captured
            seq_c += 500
            seq_s += 300

        for dx in range(data_exchanges):
            if has_seq_gap and dx == 1:
                # Segment dropped in capture
                seq_c += random.randint(300, 1200)
                t += 0.02
                continue

            payload_size = random.randint(100, 1200)
            payload = b"GET /data HTTP/1.1\r\nHost: example.com\r\n" + (b"X" * min(payload_size, 40))

            req = wrap(IP(src=client, dst=server, id=next_ipid(client, force_gap=has_id_gap and dx == 0)) / TCP(
                sport=sport, dport=80, flags="PA", seq=seq_c, ack=seq_s
            ) / Raw(load=payload))
            req.time = ts(t)
            pkts.append(req)
            seq_c += len(payload)
            t += random.uniform(0.01, 0.04)

            # Server response
            resp_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + (b"Y" * 150)
            resp = wrap(IP(src=server, dst=client, id=next_ipid(server)) / TCP(
                sport=80, dport=sport, flags="PA", seq=seq_s, ack=seq_c
            ) / Raw(load=resp_payload))
            resp.time = ts(t)
            pkts.append(resp)
            seq_s += len(resp_payload)
            t += random.uniform(0.01, 0.05)

        # 30% missing teardowns
        if random.random() > 0.30:
            fin = wrap(IP(src=client, dst=server, id=next_ipid(client)) / TCP(
                sport=sport, dport=80, flags="FA", seq=seq_c, ack=seq_s
            ))
            fin.time = ts(t)
            pkts.append(fin)
            t += 0.01

        # Occasional timestamp jump
        if random.random() < 0.12:
            t += random.uniform(5.5, 9.0)  # >5s gap
        else:
            t += random.uniform(0.05, 0.4)

    return pkts, t


def dns_queries(start_t, count=20, use_ether=False):
    pkts = []
    t = start_t
    domains = ["example.com", "google.com", "github.com", "stackoverflow.com", "python.org"]
    for i in range(count):
        client = f"192.168.1.{random.randint(10, 50)}"
        sport = random.randint(49152, 65535)
        qname = random.choice(domains)
        base = IP(src=client, dst="8.8.8.8", id=next_ipid(client)) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        if use_ether:
            base = Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:01") / base
        base.time = ts(t)
        pkts.append(base)
        t += random.uniform(0.2, 1.5)
    return pkts, t


def save_pcap(filename: str, pkts: list):
    pkts.sort(key=lambda p: float(p.time))
    path1 = os.path.join(SAMPLES_DIR, filename)
    path2 = os.path.join(UPLOADS_DIR, filename)
    wrpcap(path1, pkts)
    shutil.copyfile(path1, path2)
    size_kb = os.path.getsize(path1) / 1024
    print(f"    → {filename:30s} | {len(pkts):5d} pkts | {size_kb:6.1f} KB")


# ═══════════════════════════════════════════════════════════════════════════
# Scenarios
# ═══════════════════════════════════════════════════════════════════════════

def gen_port_scan():
    print("[1/5] Generating sample_port_scan.pcap ...")
    pkts = []

    # Background traffic with real imperfections
    bg, t = realistic_http_flows(0, 45, missing_hs_pct=0.18, gap_pct=0.15)
    pkts.extend(bg)
    dns_bg, _ = dns_queries(1, 15)
    pkts.extend(dns_bg)

    # Port scan: host 10.0.0.5 scans 250 ports on 192.168.1.100
    t = 12.0
    for port in range(1, 251):
        syn = IP(src="10.0.0.5", dst="192.168.1.100", id=next_ipid("10.0.0.5")) / TCP(
            sport=random.randint(49152, 65535), dport=port, flags="S",
            seq=random.randint(100000, 999999)
        )
        syn.time = ts(t)
        pkts.append(syn)

        if port in [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 8080]:
            resp = IP(src="192.168.1.100", dst="10.0.0.5", id=next_ipid("192.168.1.100")) / TCP(
                sport=port, dport=syn[TCP].sport, flags="SA",
                seq=random.randint(100000, 999999), ack=syn[TCP].seq + 1
            )
            resp.time = ts(t + 0.001)
            pkts.append(resp)
        else:
            resp = IP(src="192.168.1.100", dst="10.0.0.5", id=next_ipid("192.168.1.100")) / TCP(
                sport=port, dport=syn[TCP].sport, flags="RA",
                seq=0, ack=syn[TCP].seq + 1
            )
            resp.time = ts(t + 0.001)
            pkts.append(resp)

        t += random.uniform(0.001, 0.005)

    bg2, _ = realistic_http_flows(t + 3, 20, missing_hs_pct=0.10, gap_pct=0.08)
    pkts.extend(bg2)

    save_pcap("sample_port_scan.pcap", pkts)


def gen_syn_flood():
    print("[2/5] Generating sample_syn_flood.pcap ...")
    pkts = []

    bg, _ = realistic_http_flows(0, 35, missing_hs_pct=0.15, gap_pct=0.10)
    pkts.extend(bg)

    # 1000 SYNs flooded to 192.168.1.100:80 in ~4.5s
    t = 8.0
    for i in range(1000):
        src_ip = f"{random.choice([10,172,192])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        syn = IP(src=src_ip, dst="192.168.1.100", id=random.randint(1000, 60000)) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S",
            seq=random.randint(100000, 9999999)
        )
        syn.time = ts(t)
        pkts.append(syn)
        t += random.uniform(0.001, 0.007)

    # Only 5 responses sent before server queues filled
    for i in range(5):
        sa = IP(src="192.168.1.100", dst="10.1.2.3", id=next_ipid("192.168.1.100")) / TCP(
            sport=80, dport=random.randint(1024, 65535), flags="SA",
            seq=random.randint(100000, 999999)
        )
        sa.time = ts(8.5 + i * 0.4)
        pkts.append(sa)

    bg2, _ = realistic_http_flows(t + 4, 15, missing_hs_pct=0.20, gap_pct=0.15)
    pkts.extend(bg2)

    save_pcap("sample_syn_flood.pcap", pkts)


def gen_arp_spoof():
    print("[3/5] Generating sample_arp_spoof.pcap ...")
    pkts = []

    bg, _ = realistic_http_flows(0, 40, use_ether=True, missing_hs_pct=0.20, gap_pct=0.12)
    pkts.extend(bg)

    # Gateway ARP
    t = 4.0
    for i in range(10):
        arp = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        arp.time = ts(t)
        pkts.append(arp)
        t += random.uniform(1.5, 3.0)

    # Attacker ARP spoofing
    t = 6.0
    for i in range(35):
        spoof = Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="de:ad:be:ef:00:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        spoof.time = ts(t)
        pkts.append(spoof)
        t += random.uniform(0.3, 0.8)

    save_pcap("sample_arp_spoof.pcap", pkts)


def gen_ssh_brute():
    print("[4/5] Generating sample_ssh_brute.pcap ...")
    pkts = []

    bg, _ = realistic_http_flows(0, 40, missing_hs_pct=0.15, gap_pct=0.10)
    pkts.extend(bg)

    # 80 rapid SSH connections
    t = 10.0
    attacker = "10.0.0.99"
    victim = "192.168.1.100"
    for i in range(80):
        sport = random.randint(49152, 65535)
        seq_c = random.randint(100000, 999999)
        seq_s = random.randint(100000, 999999)

        syn = IP(src=attacker, dst=victim, id=next_ipid(attacker)) / TCP(
            sport=sport, dport=22, flags="S", seq=seq_c
        )
        syn.time = ts(t)
        pkts.append(syn)

        sa = IP(src=victim, dst=attacker, id=next_ipid(victim)) / TCP(
            sport=22, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1
        )
        sa.time = ts(t + 0.008)
        pkts.append(sa)

        ack = IP(src=attacker, dst=victim, id=next_ipid(attacker)) / TCP(
            sport=sport, dport=22, flags="A", seq=seq_c + 1, ack=seq_s + 1
        )
        ack.time = ts(t + 0.012)
        pkts.append(ack)

        banner = IP(src=victim, dst=attacker, id=next_ipid(victim)) / TCP(
            sport=22, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        banner.time = ts(t + 0.02)
        pkts.append(banner)

        rst = IP(src=victim, dst=attacker, id=next_ipid(victim)) / TCP(
            sport=22, dport=sport, flags="RA", seq=seq_s + 50
        )
        rst.time = ts(t + 0.25)
        pkts.append(rst)

        t += random.uniform(0.3, 0.6)

    save_pcap("sample_ssh_brute.pcap", pkts)


def gen_mixed():
    print("[5/5] Generating sample_mixed_attacks.pcap ...")
    pkts = []

    # Phase 1: Background traffic
    bg, _ = realistic_http_flows(0, 60, use_ether=True, missing_hs_pct=0.18, gap_pct=0.12)
    pkts.extend(bg)
    dns_bg, _ = dns_queries(0, 15, use_ether=True)
    pkts.extend(dns_bg)

    # Phase 2: Port scan
    t = 16.0
    for port in range(1, 180):
        syn = Ether(src="de:ad:00:00:00:05", dst="aa:bb:cc:dd:ee:64") / IP(
            src="10.0.0.5", dst="192.168.1.100", id=next_ipid("10.0.0.5")
        ) / TCP(sport=random.randint(49152, 65535), dport=port, flags="S", seq=random.randint(100000, 999999))
        syn.time = ts(t)
        pkts.append(syn)
        t += random.uniform(0.001, 0.004)

    # Phase 3: SYN flood
    t = 22.0
    for i in range(600):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        syn = Ether(
            src=f"de:ad:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}",
            dst="aa:bb:cc:dd:ee:64"
        ) / IP(src=src_ip, dst="192.168.1.100", id=random.randint(1000, 60000)) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(100000, 9999999)
        )
        syn.time = ts(t)
        pkts.append(syn)
        t += random.uniform(0.002, 0.007)

    # Phase 4: ARP spoof
    t = 28.0
    for i in range(12):
        legit = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        legit.time = ts(t)
        pkts.append(legit)
        spoof = Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="de:ad:be:ef:00:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        spoof.time = ts(t + 0.2)
        pkts.append(spoof)
        t += random.uniform(0.5, 1.0)

    # Phase 5: SSH brute force
    t = 36.0
    for i in range(55):
        sport = random.randint(49152, 65535)
        seq_c = random.randint(100000, 999999)
        syn = Ether(src="de:ad:00:00:00:99", dst="aa:bb:cc:dd:ee:64") / IP(
            src="10.0.0.99", dst="192.168.1.100", id=next_ipid("10.0.0.99")
        ) / TCP(sport=sport, dport=22, flags="S", seq=seq_c)
        syn.time = ts(t)
        pkts.append(syn)
        sa = Ether(src="aa:bb:cc:dd:ee:64", dst="de:ad:00:00:00:99") / IP(
            src="192.168.1.100", dst="10.0.0.99", id=next_ipid("192.168.1.100")
        ) / TCP(sport=22, dport=sport, flags="SA", seq=random.randint(100000, 999999), ack=seq_c + 1)
        sa.time = ts(t + 0.01)
        pkts.append(sa)
        t += random.uniform(0.3, 0.6)

    # Phase 6: Post-attack traffic
    bg2, _ = realistic_http_flows(t + 2, 25, use_ether=True, missing_hs_pct=0.15, gap_pct=0.10)
    pkts.extend(bg2)

    save_pcap("sample_mixed_attacks.pcap", pkts)


if __name__ == "__main__":
    print("=" * 65)
    print("  PacketTrust – Generating Realistic Forensics PCAP Files")
    print("=" * 65)
    print()
    gen_port_scan()
    gen_syn_flood()
    gen_arp_spoof()
    gen_ssh_brute()
    gen_mixed()
    print()
    print("All PCAP files generated and synchronized to samples/ and backend/uploads/")
