# sniffer.py
import time
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from detector import Detector
from logger import log_intrusion

detector = Detector(
    pps_threshold=200,        # tuneable: packets-per-second threshold
    window_seconds=1,
    keep_windows=6,
    sustain_windows=3,
    alert_suppression_seconds=300
)

BANNER = """
===========================================
   🔥 PyGuardian — IDS/IPS (Best Mode)
   Listening for suspicious activity...
   (Run as Administrator for blocking)
===========================================
"""

def pretty_alert(ip, action, reason="High sustained packet rate"):
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("\n" + "="*45)
    print(f"⚠️  [{action.upper()}] {reason}")
    print(f"    → Source : {ip}")
    print(f"    → Time   : {now}")
    print(f"    → Action : {'Blocked via firewall' if action == 'block' else 'Logged only'}")
    print("="*45 + "\n")

def packet_to_info(pkt):
    info = {}
    if IP in pkt:
        info["src_ip"] = pkt[IP].src
    # We only need src for rate detection. We still keep fields for future use.
    if TCP in pkt:
        info["dst_port"] = pkt[TCP].dport
        info["protocol"] = "TCP"
    elif UDP in pkt:
        info["dst_port"] = pkt[UDP].dport
        info["protocol"] = "UDP"
    elif DNS in pkt and pkt.haslayer(DNSQR):
        info["protocol"] = "DNS"
        info["domain"] = pkt[DNSQR].qname.decode(errors="ignore")
    return info

def handle_packet(pkt):
    info = packet_to_info(pkt)
    src = info.get("src_ip")
    if not src:
        return

    action = detector.observe_packet(src, now=time.time())
    if action == "block":
        pretty_alert(src, action, reason="Sustained high packet rate detected")
    # else nothing (we suppress repeated messages)

def main():
    print(BANNER)
    sniff(prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
