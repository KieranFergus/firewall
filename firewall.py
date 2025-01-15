from scapy.all import sniff, wrpcap

def packet_callback(packet):
    print(packet.summary())

packets = sniff(prn=packet_callback, count=10)
wrpcap("captures.pcap", packets)