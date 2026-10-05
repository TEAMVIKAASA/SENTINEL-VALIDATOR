from scapy.all import sniff, TCP, IP, ICMP, conf
import config
from supabase import create_client

supabase = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
print("[*] Project Sentinel Sniffer active... Listening for anomalies.")

def process_packet(pkt):
    # TCP Xmas Scan check (Flags: F, P, U -> 0x29)
    if pkt.haslayer(TCP) and (pkt[TCP].flags == 0x29 or pkt[TCP].flags == 'FPU'):
        print("[!] Detected: TCP Xmas Scan")
        supabase.table(config.ALERTS_TABLE).insert({"alert_type": "TCP Xmas Scan Detected"}).execute()

    # Oversized ICMP check
    elif pkt.haslayer(ICMP) and len(pkt) > 1000:
        print("[!] Detected: Oversized ICMP Packet")
        supabase.table(config.ALERTS_TABLE).insert({"alert_type": "ICMP Oversized Ping Detected"}).execute()

    # TCP SYN check
    elif pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        print("[!] Detected: TCP SYN Scan")
        supabase.table(config.ALERTS_TABLE).insert({"alert_type": "TCP SYN Burst Detected"}).execute()

# Windows Npcap Loopback Adapter automatically select karne ke liye
loopback_iface = conf.loopback_name or "Npcap Loopback Adapter"

try:
    sniff(iface=loopback_iface, prn=process_packet, store=0)
except Exception:
    # Fallback to default sniffing
    sniff(prn=process_packet, store=0)