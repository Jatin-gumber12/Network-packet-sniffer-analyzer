import csv
import netifaces
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Detect active interface
def get_active_interface():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip_addr = ip_info.get("addr")
            if ip_addr != "127.0.0.1":  # ignore loopback
                return iface
    return None

# Callback to process each packet
def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocol name
        if proto == 1:
            proto_name = "ICMP"
        elif proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto)

        # Print summary
        print(f"{src} -> {dst} ({proto_name})")

        # Write to CSV
        with open("packets.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([src, dst, proto_name])

if __name__ == "__main__":
    iface = get_active_interface()
    if iface is None:
        print("No active network interface found.")
        exit(1)

    # Initialize CSV with header
    with open("packets.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dst_ip", "protocol"])

    print(f"[*] Starting packet capture on interface: {iface}")
    print("[*] Press Ctrl+C to stop.")

    sniff(iface=iface, prn=packet_callback, store=False)
