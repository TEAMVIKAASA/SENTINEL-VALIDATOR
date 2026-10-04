import time
from scapy.all import IP, TCP, ICMP, send
import config

def trigger_xmas_scan(target_ip=config.TARGET_IP, target_port=config.TARGET_PORT):
    """
    Sends a single TCP packet with FIN, PSH, and URG flags set simultaneously.
    Classic stealth scan vector that standard IDS rules flag immediately.
    """
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FPU")
    send(packet, verbose=False)
    print(f"[+] Dispatched Xmas Scan packet -> {target_ip}:{target_port}")

def trigger_oversized_icmp(target_ip=config.TARGET_IP):
    """
    Sends an ICMP Echo Request with an unusually large 1200-byte payload
    to trigger buffer/payload length anomaly detection.
    """
    payload = b"X" * 1200
    packet = IP(dst=target_ip) / ICMP() / payload
    send(packet, verbose=False)
    print(f"[+] Dispatched Oversized ICMP Echo (1200B) -> {target_ip}")

def trigger_syn_burst(target_ip=config.TARGET_IP, target_port=config.TARGET_PORT, count=config.PACKET_COUNT):
    """
    Sends a rapid series of TCP SYN packets without completing handshakes
    to test rate-limiting and SYN flood thresholds.
    """
    for i in range(count):
        # Varying source ports to simulate distinct incoming connections
        packet = IP(dst=target_ip) / TCP(sport=1024 + i, dport=target_port, flags="S")
        send(packet, verbose=False)
    print(f"[+] Dispatched {count} SYN packets -> {target_ip}:{target_port}")

if __name__ == "__main__":
    # Standalone quick test execution
    print("[*] Running quick test dispatch on loopback...")
    trigger_xmas_scan()