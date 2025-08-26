from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())  # Print a one-line summary of each packet

# Capture packets on your WiFi interface
print("Starting packet capture on interface 'wlo1'...")
sniff(iface="wlo1", prn=packet_callback, store=False)
