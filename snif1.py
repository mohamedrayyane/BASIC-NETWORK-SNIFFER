from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[+] Packet: {ip_src} --> {ip_dst} | Protocol: {proto}")

        if packet.haslayer(TCP):
            print("    [TCP] Src Port:", packet[TCP].sport, "| Dst Port:", packet[TCP].dport)
        elif packet.haslayer(UDP):
            print("    [UDP] Src Port:", packet[UDP].sport, "| Dst Port:", packet[UDP].dport)
        elif packet.haslayer(ICMP):
            print("    [ICMP] Type:", packet[ICMP].type)

# Start sniffing
print("[*] Starting packet sniffer...")
sniff(prn=process_packet, store=0)
