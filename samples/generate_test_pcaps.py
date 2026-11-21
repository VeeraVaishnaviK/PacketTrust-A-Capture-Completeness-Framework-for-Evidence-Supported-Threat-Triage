"""
generate_test_pcaps.py – Create multiple test PCAP files for PacketTrust.

Generates 5 distinct scenarios:
  1. sample_port_scan.pcap       – Port scan + normal traffic
  2. sample_syn_flood.pcap       – SYN flood attack
  3. sample_arp_spoof.pcap       – ARP spoofing with normal traffic
  4. sample_ssh_brute.pcap       – SSH brute force attempts
  5. sample_mixed_attacks.pcap   – All 4 attacks combined (full scenario)

Each file is self-contained with realistic background traffic.
"""

import os
import random
import sys

from scapy.all import IP, TCP, UDP, Ether, ARP, ICMP, DNS, DNSQR, Raw, wrpcap

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
os.makedirs(OUT_DIR, exist_ok=True)

random.seed(42)
BASE_TIME = 1700000000.0


def ts(offset):
    return BASE_TIME + offset


def normal_http_traffic(start_t, count=100, use_ether=False):
    """Generate normal HTTP request/response-like TCP traffic."""
    pkts = []
    t = start_t
    for i in range(count):
        sport = random.randint(49152, 65535)
        client = f"192.168.1.{random.randint(10, 50)}"
        server = random.choice(["93.184.216.34", "142.250.80.46", "151.101.1.69"])
        client_mac = "aa:bb:cc:dd:ee:10"
        server_mac = "aa:bb:cc:dd:ee:01"

        base_cs = (Ether(src=client_mac, dst=server_mac) / IP(src=client, dst=server)) if use_ether else IP(src=client, dst=server)
        base_sc = (Ether(src=server_mac, dst=client_mac) / IP(src=server, dst=client)) if use_ether else IP(src=server, dst=client)

        # SYN
        syn = base_cs / TCP(sport=sport, dport=80, flags="S", seq=random.randint(1000, 99999))
        syn.time = ts(t)
        pkts.append(syn)

        # SYN-ACK
        sa = base_sc / TCP(sport=80, dport=sport, flags="SA", seq=random.randint(1000, 99999), ack=syn[TCP].seq + 1)
        sa.time = ts(t + 0.02)
        pkts.append(sa)

        # ACK
        ack = base_cs / TCP(sport=sport, dport=80, flags="A", seq=syn[TCP].seq + 1, ack=sa[TCP].seq + 1)
        ack.time = ts(t + 0.03)
        pkts.append(ack)

        # Data (HTTP GET)
        data = base_cs / TCP(sport=sport, dport=80, flags="PA", seq=syn[TCP].seq + 1, ack=sa[TCP].seq + 1) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data.time = ts(t + 0.04)
        pkts.append(data)

        t += random.uniform(0.1, 0.5)
    return pkts, t


def dns_traffic(start_t, count=30):
    """Generate DNS query/response traffic."""
    pkts = []
    t = start_t
    domains = ["example.com", "google.com", "github.com", "stackoverflow.com", "python.org"]
    for i in range(count):
        client = f"192.168.1.{random.randint(10, 50)}"
        dns_server = "8.8.8.8"
        qname = random.choice(domains)
        sport = random.randint(49152, 65535)

        q = IP(src=client, dst=dns_server) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        q.time = ts(t)
        pkts.append(q)
        t += random.uniform(0.5, 2.0)
    return pkts, t


def icmp_traffic(start_t, count=20, use_ether=False):
    """Generate ICMP ping traffic."""
    pkts = []
    t = start_t
    for i in range(count):
        src = "192.168.1.10"
        dst = f"192.168.1.{random.randint(1, 254)}"
        src_mac = "aa:bb:cc:dd:ee:10"
        dst_mac = "aa:bb:cc:dd:ee:01"

        base_sd = (Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst)) if use_ether else IP(src=src, dst=dst)
        base_ds = (Ether(src=dst_mac, dst=src_mac) / IP(src=dst, dst=src)) if use_ether else IP(src=dst, dst=src)

        req = base_sd / ICMP(type=8) / Raw(load=b"A" * 32)
        req.time = ts(t)
        pkts.append(req)

        reply = base_ds / ICMP(type=0) / Raw(load=b"A" * 32)
        reply.time = ts(t + 0.005)
        pkts.append(reply)
        t += 1.0
    return pkts, t


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 1: Port Scan
# ═══════════════════════════════════════════════════════════════════════════
def gen_port_scan():
    print("[1/5] Generating sample_port_scan.pcap ...")
    pkts = []

    # Background traffic
    bg, t = normal_http_traffic(0, 80)
    pkts.extend(bg)

    dns_bg, _ = dns_traffic(2, 20)
    pkts.extend(dns_bg)

    # Port scan: attacker SYNs 200 ports on victim
    t = 10.0
    for port in range(1, 201):
        syn = IP(src="10.0.0.5", dst="192.168.1.100") / TCP(
            sport=random.randint(49152, 65535), dport=port, flags="S",
            seq=random.randint(1000, 99999)
        )
        syn.time = ts(t)
        pkts.append(syn)

        # Some ports respond RST, some SYN-ACK (open)
        if port in [22, 80, 443, 3306, 8080]:
            resp = IP(src="192.168.1.100", dst="10.0.0.5") / TCP(
                sport=port, dport=syn[TCP].sport, flags="SA",
                seq=random.randint(1000, 99999), ack=syn[TCP].seq + 1
            )
        else:
            resp = IP(src="192.168.1.100", dst="10.0.0.5") / TCP(
                sport=port, dport=syn[TCP].sport, flags="RA",
                seq=0, ack=syn[TCP].seq + 1
            )
        resp.time = ts(t + 0.001)
        pkts.append(resp)
        t += 0.003

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(OUT_DIR, "sample_port_scan.pcap"), pkts)
    print(f"    → {len(pkts)} packets")


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 2: SYN Flood
# ═══════════════════════════════════════════════════════════════════════════
def gen_syn_flood():
    print("[2/5] Generating sample_syn_flood.pcap ...")
    pkts = []

    bg, _ = normal_http_traffic(0, 50)
    pkts.extend(bg)

    # SYN flood: 800 SYNs from random spoofed IPs to victim:80 in ~3s
    t = 5.0
    for i in range(800):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        syn = IP(src=src_ip, dst="192.168.1.100") / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S",
            seq=random.randint(1000, 999999)
        )
        syn.time = ts(t)
        pkts.append(syn)
        t += random.uniform(0.002, 0.006)

    # Victim tries to SYN-ACK but only manages a few
    for i in range(15):
        sa = IP(src="192.168.1.100", dst=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") / TCP(
            sport=80, dport=random.randint(1024, 65535), flags="SA",
            seq=random.randint(1000, 99999)
        )
        sa.time = ts(5.5 + i * 0.1)
        pkts.append(sa)

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(OUT_DIR, "sample_syn_flood.pcap"), pkts)
    print(f"    → {len(pkts)} packets")


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 3: ARP Spoofing
# ═══════════════════════════════════════════════════════════════════════════
def gen_arp_spoof():
    print("[3/5] Generating sample_arp_spoof.pcap ...")
    pkts = []

    # Use Ether frames for all traffic so linktype is consistent with ARP
    bg, _ = normal_http_traffic(0, 60, use_ether=True)
    pkts.extend(bg)

    icmp_bg, _ = icmp_traffic(1, 15, use_ether=True)
    pkts.extend(icmp_bg)

    # Normal ARP: gateway 192.168.1.1 is aa:bb:cc:dd:ee:01
    t = 5.0
    for i in range(10):
        arp = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        arp.time = ts(t)
        pkts.append(arp)
        t += 2.0

    # ARP spoof: attacker claims to be 192.168.1.1 with different MAC
    t = 8.0
    for i in range(30):
        spoof = Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc="de:ad:be:ef:00:01", psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:10", pdst="192.168.1.10"
        )
        spoof.time = ts(t)
        pkts.append(spoof)
        t += 0.5

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(OUT_DIR, "sample_arp_spoof.pcap"), pkts)
    print(f"    → {len(pkts)} packets")


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 4: SSH Brute Force
# ═══════════════════════════════════════════════════════════════════════════
def gen_ssh_brute():
    print("[4/5] Generating sample_ssh_brute.pcap ...")
    pkts = []

    bg, _ = normal_http_traffic(0, 70)
    pkts.extend(bg)

    dns_bg, _ = dns_traffic(0, 15)
    pkts.extend(dns_bg)

    # SSH brute force: 60 connection attempts from attacker in ~30s
    t = 10.0
    attacker = "10.0.0.99"
    victim = "192.168.1.100"
    for i in range(60):
        sport = random.randint(49152, 65535)

        # SYN
        syn = IP(src=attacker, dst=victim) / TCP(
            sport=sport, dport=22, flags="S",
            seq=random.randint(1000, 99999)
        )
        syn.time = ts(t)
        pkts.append(syn)

        # SYN-ACK
        sa = IP(src=victim, dst=attacker) / TCP(
            sport=22, dport=sport, flags="SA",
            seq=random.randint(1000, 99999), ack=syn[TCP].seq + 1
        )
        sa.time = ts(t + 0.01)
        pkts.append(sa)

        # ACK
        ack = IP(src=attacker, dst=victim) / TCP(
            sport=sport, dport=22, flags="A",
            seq=syn[TCP].seq + 1, ack=sa[TCP].seq + 1
        )
        ack.time = ts(t + 0.02)
        pkts.append(ack)

        # SSH banner
        banner = IP(src=victim, dst=attacker) / TCP(
            sport=22, dport=sport, flags="PA",
            seq=sa[TCP].seq + 1, ack=syn[TCP].seq + 1
        ) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        banner.time = ts(t + 0.03)
        pkts.append(banner)

        # RST after failed auth
        rst = IP(src=victim, dst=attacker) / TCP(
            sport=22, dport=sport, flags="RA",
            seq=sa[TCP].seq + 50
        )
        rst.time = ts(t + 0.3)
        pkts.append(rst)

        t += random.uniform(0.4, 0.8)

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(OUT_DIR, "sample_ssh_brute.pcap"), pkts)
    print(f"    → {len(pkts)} packets")


# ═══════════════════════════════════════════════════════════════════════════
# Scenario 5: Mixed Attacks (all combined)
# ═══════════════════════════════════════════════════════════════════════════
def gen_mixed():
    print("[5/5] Generating sample_mixed_attacks.pcap ...")
    pkts = []

    # Use Ether frames for all traffic (consistent linktype with ARP)
    # Phase 1: Normal traffic (0-10s)
    bg, _ = normal_http_traffic(0, 120, use_ether=True)
    pkts.extend(bg)
    dns_bg, _ = dns_traffic(0, 25)
    # Wrap DNS in Ether
    for p in dns_bg:
        ep = Ether(src="aa:bb:cc:dd:ee:10", dst="aa:bb:cc:dd:ee:01") / p
        ep.time = p.time
        pkts.append(ep)
    icmp_bg, _ = icmp_traffic(0, 10, use_ether=True)
    pkts.extend(icmp_bg)

    # Phase 2: Port scan (15-17s)
    t = 15.0
    for port in range(1, 151):
        syn = Ether(src="de:ad:00:00:00:05", dst="aa:bb:cc:dd:ee:64") / IP(src="10.0.0.5", dst="192.168.1.100") / TCP(
            sport=random.randint(49152, 65535), dport=port, flags="S",
            seq=random.randint(1000, 99999)
        )
        syn.time = ts(t)
        pkts.append(syn)
        t += 0.002

    # Phase 3: SYN flood (20-24s)
    t = 20.0
    for i in range(500):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        syn = Ether(src=f"de:ad:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}", dst="aa:bb:cc:dd:ee:64") / IP(src=src_ip, dst="192.168.1.100") / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S",
            seq=random.randint(1000, 999999)
        )
        syn.time = ts(t)
        pkts.append(syn)
        t += 0.005

    # Phase 4: ARP spoof (28-35s)
    t = 28.0
    for i in range(10):
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
        spoof.time = ts(t + 0.3)
        pkts.append(spoof)
        t += 0.8

    # Phase 5: SSH brute force (38-55s)
    t = 38.0
    for i in range(45):
        sport = random.randint(49152, 65535)
        syn = Ether(src="de:ad:00:00:00:99", dst="aa:bb:cc:dd:ee:64") / IP(src="10.0.0.99", dst="192.168.1.100") / TCP(
            sport=sport, dport=22, flags="S",
            seq=random.randint(1000, 99999)
        )
        syn.time = ts(t)
        pkts.append(syn)

        sa = Ether(src="aa:bb:cc:dd:ee:64", dst="de:ad:00:00:00:99") / IP(src="192.168.1.100", dst="10.0.0.99") / TCP(
            sport=22, dport=sport, flags="SA",
            seq=random.randint(1000, 99999), ack=syn[TCP].seq + 1
        )
        sa.time = ts(t + 0.01)
        pkts.append(sa)
        t += 0.4

    # Phase 6: More normal traffic (55-65s)
    bg2, _ = normal_http_traffic(55, 60, use_ether=True)
    pkts.extend(bg2)

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(OUT_DIR, "sample_mixed_attacks.pcap"), pkts)
    print(f"    → {len(pkts)} packets")


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  PacketTrust – Test PCAP Generator")
    print("=" * 55)
    print()
    gen_port_scan()
    gen_syn_flood()
    gen_arp_spoof()
    gen_ssh_brute()
    gen_mixed()
    print()
    print("✅ All 5 test PCAPs generated in:", OUT_DIR)
    print()
    for f in sorted(os.listdir(OUT_DIR)):
        if f.endswith(".pcap"):
            size = os.path.getsize(os.path.join(OUT_DIR, f))
            print(f"   {f:35s}  {size/1024:.1f} KB")
