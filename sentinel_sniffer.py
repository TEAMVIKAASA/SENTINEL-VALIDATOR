import time
from scapy.all import sniff, IP, TCP, ICMP, conf
import config
from supabase import create_client

supabase = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
print("[*] Project Sentinel Core IDS Engine online. Listening for protocol anomalies...")

def inspect_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # 1. Detect TCP Xmas Scan (Flags: FIN, PSH, URG -> 0x29 / FPU)
    if pkt.haslayer(TCP) and (pkt[TCP].flags == 0x29 or pkt[TCP].flags == "FPU"):
        print(f"[!] THREAT DETECTED: TCP Xmas Scan from {src_ip}:{pkt[TCP].sport} -> port {pkt[TCP].dport}")
        supabase.table(config.ALERTS_TABLE).insert({
            "alert_type": "TCP Xmas Scan Detected",
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "target_port": pkt[TCP].dport,
            "severity": "High",
            "action_taken": "Logged"
        }).execute()

    # 2. Detect Oversized ICMP Echo Requests (> 1000 Bytes)
    elif pkt.haslayer(ICMP) and len(pkt) > 1000:
        print(f"[!] THREAT DETECTED: Oversized ICMP packet ({len(pkt)}B) from {src_ip}")
        supabase.table(config.ALERTS_TABLE).insert({
            "alert_type": "Oversized ICMP Ping Detected",
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "severity": "Medium",
            "action_taken": "Logged"
        }).execute()

    # 3. Detect TCP SYN Scans / Bursts
    elif pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        print(f"[!] THREAT DETECTED: TCP SYN Burst/Sweep on port {pkt[TCP].dport} from {src_ip}")
        supabase.table(config.ALERTS_TABLE).insert({
            "alert_type": "TCP SYN Burst Detected",
            "source_ip": src_ip,
            "target_ip": dst_ip,
            "target_port": pkt[TCP].dport,
            "severity": "Critical",
            "action_taken": "Blocked"
        }).execute()

# Sniff packets across active interfaces
try:
    sniff(prn=inspect_packet, store=0)
except Exception as e:
    print(f"[-] Sniffer encountered an exception: {e}")