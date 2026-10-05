import logging
from scapy.all import IP, TCP, ICMP, send
import config

logger = logging.getLogger(__name__)

def trigger_xmas_scan():
    """Dispatches a TCP packet with FIN, PSH, and URG flags set."""
    target_ip = config.TARGET_IP
    target_port = config.TARGET_PORT
    print(f"[+] Dispatching Xmas Scan packet (Flags: FPU) -> {target_ip}:{target_port}")
    
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="FPU")
    try:
        send(pkt, verbose=False)
    except Exception:
        logger.exception("Failed to dispatch Xmas scan packet")

def trigger_oversized_icmp():
    """Dispatches an oversized ICMP ping request payload."""
    target_ip = config.TARGET_IP
    payload = "X" * 1200
    print(f"[+] Dispatching Oversized ICMP Echo ({len(payload)} bytes) -> {target_ip}")
    
    pkt = IP(dst=target_ip) / ICMP() / payload
    try:
        send(pkt, verbose=False)
    except Exception:
        logger.exception("Failed to dispatch oversized ICMP packet")

def trigger_syn_burst():
    """Dispatches a burst of TCP SYN packets simulating a SYN flood/sweep."""
    target_ip = config.TARGET_IP
    target_port = config.TARGET_PORT
    count = config.PACKET_COUNT
    print(f"[+] Dispatching {count} SYN packets -> {target_ip}:{target_port}")
    
    for _ in range(count):
        pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        try:
            send(pkt, verbose=False)
        except Exception:
            logger.exception("Failed to dispatch SYN burst packet")