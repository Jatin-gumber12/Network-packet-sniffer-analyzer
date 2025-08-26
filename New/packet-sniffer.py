#!/usr/bin/env python3
"""
packet-sniffer.py
Simple readable packet sniffer (prints timestamp, proto, src/dst, ports, len).
Supports interface, BPF filter, packet count, pcap output and CSV summary.
"""

import argparse, csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap

# globals used by callback
packets_buffer = []
csv_writer = None
csv_file = None
args = None

def format_packet(pkt):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    length = len(pkt)
    # IP-based
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            proto_name = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto_name = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto_name = "ICMP"
            sport = ""
            dport = ""
        else:
            proto_name = f"IP({pkt[IP].proto})"
            sport = ""
            dport = ""
    # ARP
    elif ARP in pkt:
        proto_name = "ARP"
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        sport = ""
        dport = ""
    # fallback
    else:
        proto_name = pkt.name
        src = getattr(pkt, "src", "")
        dst = getattr(pkt, "dst", "")
        sport = ""
        dport = ""
    return ts, proto_name, src, sport, dst, dport, length

def packet_callback(pkt):
    global csv_writer, packets_buffer
    ts, proto_name, src, sport, dst, dport, length = format_packet(pkt)
    if sport and dport:
        line = f"[{ts}] {proto_name} {src}:{sport} -> {dst}:{dport} len={length}"
    else:
        line = f"[{ts}] {proto_name} {src} -> {dst} len={length}"
    print(line)

    # optional CSV logging
    if args.csv:
        csv_writer.writerow([ts, proto_name, src, sport, dst, dport, length])

    # store packet for optional pcap output
    if args.write:
        packets_buffer.append(pkt)

def main():
    global args, csv_writer, csv_file
    parser = argparse.ArgumentParser(description="Packet sniffer - readable output.")
    parser.add_argument("-i", "--interface", help="Interface to sniff (default: autodetect)", default=None)
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 = infinite)", type=int, default=0)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp port 80')", default=None)
    parser.add_argument("-w", "--write", help="Write captured packets to pcap file (e.g. out.pcap)", default=None)
    parser.add_argument("--csv", help="Write summary CSV (e.g. summary.csv)", default=None)
    args = parser.parse_args()

    if args.csv:
        csv_file = open(args.csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp","protocol","src_ip","src_port","dst_ip","dst_port","length"])

    try:
        # scapy sniff: count=None => infinite
        scount = args.count if args.count and args.count > 0 else None
        print(f"Sniffing on iface={args.interface or 'default'} filter={args.filter or 'none'} count={args.count}")
        sniff(prn=packet_callback, iface=args.interface, filter=args.filter, count=scount, store=False)
    except KeyboardInterrupt:
        print("\nStopped by user (Ctrl+C)")
    finally:
        if args.write and packets_buffer:
            wrpcap(args.write, packets_buffer)
            print(f"Wrote {len(packets_buffer)} packets to {args.write}")
        if args.csv:
            csv_file.close()
            print(f"Wrote CSV summary to {args.csv}")

if __name__ == "main":
    main()
