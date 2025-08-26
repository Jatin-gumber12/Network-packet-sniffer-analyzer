from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

if __name__ == "main":
    # Change interface to your real one (like "wlo1" or "eth0")
    sniff(iface="wlo1", prn=packet_callback, store=False)
