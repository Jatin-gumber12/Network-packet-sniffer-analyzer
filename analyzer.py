# analyzer.py
import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

DB_FILE = "packets.db"

# --------------------------
# Initialize SQLite database
# --------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            protocol TEXT PRIMARY KEY,
            count INTEGER
        )
    """)

    # Prepopulate protocol stats
    for proto in ["TCP", "UDP", "ICMP", "Other"]:
        cursor.execute("INSERT OR IGNORE INTO stats (protocol, count) VALUES (?, ?)", (proto, 0))

    conn.commit()
    conn.close()


# --------------------------
# Packet Processing
# --------------------------
def process_packet(packet):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        # Identify protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Insert into packets table
        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, protocol, length))

        # Update stats
        cursor.execute("""
            UPDATE stats SET count = count + 1 WHERE protocol = ?
        """, (protocol,))

        conn.commit()

    conn.close()


# --------------------------
# Main Sniffer Function
# --------------------------
def start_analyzer(interface):
    print(f"[+] Starting packet analyzer on {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)


if __name__ == "__main__":
    import netifaces

    # Show available interfaces (like in sniffer.py)
    print("Available Network Interfaces:")
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs.get(netifaces.AF_INET, [{"addr": "No IP"}])[0]["addr"]
        print(f" - {iface}: {ip_info}")

    iface = input("\nEnter the interface to analyze: ").strip()

    init_db()
    start_analyzer(iface)
