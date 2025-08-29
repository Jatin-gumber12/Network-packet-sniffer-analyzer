import socket
import struct
import textwrap
import netifaces

# ----------------- Helper Functions -----------------
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def ipv4(addr):
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# ----------------- Packet Handlers -----------------
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ipv4(src), ipv4(target), proto, data[header_length:]

# ----------------- Interface Selection -----------------
def list_interfaces():
    print("\nAvailable Network Interfaces:")
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        ip = addrs.get(netifaces.AF_INET, [{'addr': 'No IP'}])[0]['addr']
        print(f" - {iface}: {ip}")

# ----------------- Main -----------------
def main():
    # List interfaces
    list_interfaces()
    iface = input("\nEnter the interface to sniff on: ").strip()

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((iface, 0))
        print(f"\n🚀 Sniffing started on {iface}... Press Ctrl+C to stop.\n")
    except PermissionError:
        print("❌ Run with sudo/root privileges.")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            src_ip, dst_ip, proto, data = ipv4_packet(data)
            print(f"IPv4 Packet | Protocol: {proto} | {src_ip} -> {dst_ip}")

if __name__ == "__main__":
    main()
