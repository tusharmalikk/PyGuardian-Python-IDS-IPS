import os
import time
import re
from datetime import datetime

LOG_FOLDER = "logs"
ALERTS_LOG = os.path.join(LOG_FOLDER, "alerts.log")
BLOCKED_IPS = os.path.join(LOG_FOLDER, "blocked_ips.txt")

CHECK_INTERVAL = 1  # check every second for faster response

def get_blocked_ips():
    if not os.path.exists(BLOCKED_IPS):
        return []
    with open(BLOCKED_IPS, "r") as f:
        return [line.strip() for line in f.readlines()]

def add_blocked_ip(ip):
    with open(BLOCKED_IPS, "a") as f:
        f.write(ip + "\n")

def block_ip(ip_address):
    if os.name == "nt":  # Windows
        os.system(f'netsh advfirewall firewall add rule name="BlockIP_{ip_address}" dir=in action=block remoteip={ip_address}')
    else:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    add_blocked_ip(ip_address)
    print(f"\033[91m[BLOCKED]\033[0m {ip_address} - {datetime.now().strftime('%H:%M:%S')}")

def extract_ips_from_alert(alert_line):
    return re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", alert_line)

def print_alert(ip, alert_type):
    print(f"\033[93m[ALERT]\033[0m {alert_type} from {ip} at {datetime.now().strftime('%H:%M:%S')}")

def monitor_logs():
    print("\033[92m[INFO] Starting PyGuardian IPS Mode...\033[0m")
    blocked_ips = get_blocked_ips()
    file_position = 0

    while True:
        if os.path.exists(ALERTS_LOG):
            with open(ALERTS_LOG, "r") as f:
                # Move to last read position
                f.seek(file_position)
                lines = f.readlines()
                file_position = f.tell()  # remember new position

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    ips = extract_ips_from_alert(line)
                    for ip in ips:
                        if ip not in blocked_ips:
                            print_alert(ip, line)
                            block_ip(ip)
                            blocked_ips.append(ip)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_logs()
